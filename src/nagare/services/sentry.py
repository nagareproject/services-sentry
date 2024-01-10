# --
# Copyright (c) 2008-2023 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import re
import sys
import json
import string
import textwrap
from functools import partial

import sentry_sdk
from sentry_sdk import *  # noqa: F403
from sentry_sdk.integrations import _wsgi_common

from nagare.server import reference
from nagare.services import plugin

SPECS = {
    type(None): lambda v: 'string(default=None)',
    list: lambda v: 'list(default=list())',
    bool: lambda v: f'boolean(default={v})',
    int: lambda v: f'integer(default={v})',
    float: lambda v: f'float(default={v})',
    str: lambda v: f'string(default="{v}")',
}


def capture_event(event, hint=None):
    return sentry_sdk.capture_event(event, hint)


def capture_message(message, level=None):
    return sentry_sdk.capture_message(message, level)


def capture_exception(exception=None, simplified=True):
    exc_type, exc_value, exc_tb = sentry_sdk.utils.exc_info_from_error(
        sys.exc_info() if exception is None else exception
    )

    tb = last_chain_seen = exc_tb
    while simplified and tb:
        func_name = tb.tb_frame.f_code.co_name
        tb = tb.tb_next
        if (tb is not None) and (func_name == 'handle_request'):
            last_chain_seen = tb

    event, hint = sentry_sdk.utils.event_from_exception((exc_type, exc_value, last_chain_seen or exc_tb))

    return capture_event(event, hint)


try:
    from nagare import security

    def event_from_user():
        user = security.get_user()
        if user is None:
            user_infos = {}
        else:
            credentials = user.credentials.copy()
            for password in ('password', 'passwd', 'pass'):
                credentials.pop(password, None)

            user_infos = {'id': user.id, 'repr': str(user), 'credentials': credentials}

        return user_infos

except ImportError:

    def event_from_user():
        return {}


try:
    from nagare import i18n

    def get_current_lang():
        locale = i18n.get_locale()
        return str(locale) if locale is not None else None

except ImportError:

    def get_current_lang():
        return None


class RequestExtractor(_wsgi_common.RequestExtractor):
    def url(self):
        return self.request.path_url

    def env(self):
        return self.request.environ

    def cookies(self):
        return self.request.cookies

    def raw_data(self):
        return self.request.text

    def form(self):
        return {key: value for key, value in self.request.POST.items() if not getattr(value, 'filename', None)}

    def files(self):
        return {key: value for key, value in self.request.POST.items() if getattr(value, 'filename', None)}

    def size_of_file(self, postdata):
        file = postdata.file
        try:
            return os.fstat(file.fileno()).st_size
        except Exception:  # noqa: BLE001
            return 0

    def extract_into_event(self, event, send_default_pii):
        headers = dict(self.request.headers)
        headers.pop('Cookie', None)

        request = {
            'method': self.request.method,
            'url': self.request.create_redirect_url(),
            'query_string': self.request.query_string,
            'is_xhr': self.request.is_xhr,
            'headers': headers,
        }

        if send_default_pii:
            request['remote_addr'] = self.request.client_addr
            event.setdefault('user', {})['ip_address'] = self.request.client_addr

        event['request'] = request

        super().extract_into_event(event)


class Sentry(plugin.Plugin):
    LOAD_PRIORITY = 109  # After the state service

    FEEDBACK_JS_BUNDLE = 'https://browser.sentry-cdn.com/7.92.0/bundle.min.js'
    FEEDBACK_JS_BUNDLE_HASH = 'sha384-PaMNszg+sDbg02/rYA8+sZix+6JostQcYzgXZcSQZ68OkOkQttR9TV025MWCZE7O'
    FEEDBACK_JS = textwrap.dedent(
        """\
        <script src="{}" integrity="{}" crossorigin="anonymous"></script>
        <script>Sentry.init({{dsn: "%s"}}); Sentry.showReportDialog(%s);</script>
        """
    )
    DEFAULT_INTEGRATIONS = {
        'sentry_sdk.integrations.dedupe:DedupeIntegration',
        'sentry_sdk.integrations.atexit:AtexitIntegration',
        'sentry_sdk.integrations.argv:ArgvIntegration',
    }

    CONFIG_SPEC = dict(
        plugin.Plugin.CONFIG_SPEC,
        dsn='string',
        simplified='boolean(default=True, help="simplified or full traceback")',
        release='string(default="$app_version")',
        integrations='string_list(default=list({}))'.format(
            ', '.join(f'"{integration}"' for integration in DEFAULT_INTEGRATIONS)
        ),
        user_feedback={
            'activated': 'boolean(default=False)',
            'lang': 'string(default=None)',
            'title': 'string(default=None)',
            'subtitle': 'string(default=None)',
            'subtitle2': 'string(default=None)',
            'label_name': 'string(default=None)',
            'label_email': 'string(default=None)',
            'label_comments': 'string(default=None)',
            'label_close': 'string(default=None)',
            'label_submit': 'string(default=None)',
            'error_generic': 'string(default=None)',
            'error_form_entry': 'string(default=None)',
            'success_message': 'string(default=None)',
        },
        tags={'application': 'string(default="$app_name")', '___many___': 'string()'},
        **{
            name: SPECS[type(value)](value)
            for name, value in sentry_sdk.consts.DEFAULT_OPTIONS.items()
            if not name.startswith(('_', 'dsn', 'dist', 'default_integrations', 'integrations', 'transport', 'release'))
        },
    )

    def __init__(
        self,
        name,
        dist,
        dsn,
        simplified,
        send_default_pii,
        user_feedback,
        tags,
        integrations,
        exceptions_service,
        services_service,
        security_service=None,
        **config,
    ):
        services_service(
            super().__init__,
            name,
            dist,
            dsn=dsn,
            simplified=simplified,
            send_default_pii=send_default_pii,
            user_feedback=user_feedback,
            tags=tags,
            integration=integrations,
            **config,
        )
        self.dsn = dsn
        self.simplified = simplified
        self.send_default_pii = send_default_pii
        self.tags = tags
        self.security_service = security_service
        self.user_feedback = {
            re.sub('_(.)', lambda m: m.group(1).upper(), k): v for k, v in user_feedback.items() if v is not None
        }

        config = {k: v for k, v in config.items() if k not in plugin.Plugin.CONFIG_SPEC}

        for function_ref in ['before_send', 'before_breadcrumb', 'traces_sampler']:
            if config[function_ref] is not None:
                config[function_ref] = reference.load_object(config[function_ref])[0]

        if config['before_breadcrumb']:
            config['before_breadcrumb'] = reference.load_object(config['before_breadcrumb'])[0]

        sentry_sdk.init(
            dsn,
            send_default_pii=send_default_pii,
            default_integrations=False,
            integrations=[reference.load_object(integration)[0]() for integration in integrations],
            **config,
        )

        exceptions_service.add_exception_handler(self.handle_exception)

    def process_event(self, event, hint, request=None, session_id=None, **params):
        tags = event.setdefault('tags', {})

        if session_id is not None:
            tags['session'] = session_id

        tags.update(self.tags)

        if self.send_default_pii:
            event['user'] = event_from_user()

        if request is not None:
            RequestExtractor(request).extract_into_event(event, self.send_default_pii)

        return event

    def handle_request(self, chain, **params):
        with sentry_sdk.configure_scope() as scope:
            scope.add_event_processor(partial(self.process_event, **params))

            return chain.next(**params)

    def handle_exception(self, exception, **params):
        status_code = getattr(exception, 'status_code', None)

        if not status_code or (status_code // 100 == 5):
            event_id = capture_exception(simplified=self.simplified)

            if status_code and self.user_feedback['activated'] and event_id:
                feedback_config = dict(self.user_feedback, eventId=event_id)
                current_lang = get_current_lang()
                if ('lang' not in self.user_feedback) and (current_lang is not None):
                    feedback_config['lang'] = current_lang

                feedback_script = self.FEEDBACK_JS.format(self.FEEDBACK_JS_BUNDLE, self.FEEDBACK_JS_BUNDLE_HASH) % (
                    self.dsn,
                    json.dumps(feedback_config),
                )

                if exception.has_body:
                    before, body_end, after = exception.text.partition('</body>')
                    if body_end:
                        exception.text = before + feedback_script + body_end + after
                else:
                    template = exception.body_template_obj.template
                    exception.body_template_obj = string.Template(template + feedback_script)

        return exception
