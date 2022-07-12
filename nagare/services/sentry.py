# Encoding: utf-8

# --
# Copyright (c) 2008-2022 Net-ng.
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

import sentry_sdk
from sentry_sdk.integrations import _wsgi_common

from nagare.services import plugin
from nagare.server import reference

try:
    from nagare import security

    def event_from_user():
        user = security.get_user()

        return {'id': user.id, 'repr': str(user), 'credentials': user.credentials} if user is not None else {}
except ImportError:
    def event_from_user():
        return {}

SPECS = {
    type(None): lambda v: 'string(default=None)',
    list: lambda v: 'list(default=list())',
    bool: lambda v: 'boolean(default={})'.format(v),
    int: lambda v: 'integer(default={})'.format(v),
    float: lambda v: 'float(default={})'.format(v),
    str: lambda v: 'string(default="{}")'.format(v)
}


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
        return {
            key: value
            for key, value in self.request.POST.items()
            if not getattr(value, 'filename', None)
        }

    def files(self):
        return {
            key: value
            for key, value in self.request.POST.items()
            if getattr(value, 'filename', None)
        }

    def size_of_file(self, postdata):
        file = postdata.file
        try:
            return os.fstat(file.fileno()).st_size
        except Exception:
            return 0

    def extract_into_event(self, event, send_default_pii):
        headers = dict(self.request.headers)
        headers.pop('Cookie', None)

        request = {
            'method': self.request.method,
            'url': self.request.create_redirect_url(),
            'query_string': self.request.query_string,
            'is_xhr': self.request.is_xhr,
            'headers': headers
        }

        if send_default_pii:
            request['remote_addr'] = self.request.client_addr
            event.setdefault('user', {})['ip_address'] = self.request.client_addr

        event['request'] = request

        super(RequestExtractor, self).extract_into_event(event)


class Sentry(plugin.Plugin):
    LOAD_PRIORITY = 109  # After the state service
    DEFAULT_INTEGRATIONS = {
        # 'sentry_sdk.integrations.stdlib:StdlibIntegration',
        'sentry_sdk.integrations.dedupe:DedupeIntegration',
        'sentry_sdk.integrations.atexit:AtexitIntegration',
        'sentry_sdk.integrations.modules:ModulesIntegration',
        'sentry_sdk.integrations.argv:ArgvIntegration'
    }
    CONFIG_SPEC = dict(
        plugin.Plugin.CONFIG_SPEC,
        _app_name='string(default="$app_name")',
        dsn='string',
        simplified='boolean(default=True)',
        release='string(default="$app_name@$app_version")',
        integrations='string_list(default=list({}))'.format(', '.join(
            '"{}"'.format(integration) for integration in DEFAULT_INTEGRATIONS
        )),
        **{
            name: SPECS[type(value)](value)
            for name, value in sentry_sdk.consts.DEFAULT_OPTIONS.items()
            if not name.startswith(('_', 'dsn', 'dist', 'default_integrations', 'integrations', 'transport', 'release'))
        },
        user_feedback={
            'activated': 'boolean(default=False)',
            'title': 'string(default=None)',
            'subtitle': 'string(default=None)',
            'subtitle2': 'string(default=None)',
            'label_name': 'string(default=None)',
            'label_email': 'string(default=None)',
            'label_comments': 'string(default=None)',
            'label_close': 'string(default=None)',
            'label_submit': 'string(default=None)',
            'error_form_entry': 'string(default=None)',
            'success_message': 'string(default=None)',
        }
    )

    FEEDBACK_JS = textwrap.dedent('''\
        <script src="https://logs.net-ng.com/bundle/6.17.9/bundle.min.js"
        integrity="sha384-bg8ATkDzxNiciak2tVJV/r+DHguxvOKHQqRi2SKP2mc8IOZphuG/bYdsyBm+KQC3"
        crossorigin="anonymous"></script>

        <script>
        Sentry.init({dsn: "%s"});
        Sentry.showReportDialog(%s);
        </script>''')

    def __init__(
        self,
        name, dist,
        _app_name, dsn, simplified, send_default_pii, user_feedback, integrations,
        exceptions_service, services_service,
        **config
    ):
        services_service(
            super(Sentry, self).__init__, name, dist,
            dsn=dsn, simplified=simplified, send_default_pii=send_default_pii,
            user_feedback=user_feedback, integration=integrations,
            **config
        )
        self.app_name = _app_name
        self.dsn = dsn
        self.simplified = simplified
        self.send_default_pii = send_default_pii
        self.has_user_feedback = user_feedback.pop('activated')
        self.user_feedback = {
            re.sub('_(.)', lambda m: m.group(1).upper(), k): v
            for k, v
            in user_feedback.items()
            if v is not None
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
            **config
        )

        exceptions_service.add_http_exception_handler(self.handle_http_exception)

    def handle_request(self, chain, **params):
        sentry_sdk.set_tag('application', self.app_name)

        session_id = params.get('session_id')
        if session_id is not None:
            sentry_sdk.set_tag('session', session_id)

        return chain.next(**params)

    def event_from_exception(self, exc_type, exc_value, exc_tb):
        tb = last_chain_seen = exc_tb
        while self.simplified and tb:
            func_name = tb.tb_frame.f_code.co_name
            tb = tb.tb_next
            if (tb is not None) and (func_name == 'handle_request'):
                last_chain_seen = tb

        return sentry_sdk.utils.event_from_exception((exc_type, exc_value, last_chain_seen or exc_tb))

    def handle_http_exception(self, http_exception, request=None, **params):
        if http_exception.status_code // 100 == 5:
            event, hint = self.event_from_exception(*sys.exc_info())

            if self.send_default_pii:
                event['user'] = event_from_user()

            if request is not None:
                RequestExtractor(request).extract_into_event(event, self.send_default_pii)

            event_id = sentry_sdk.capture_event(event, hint=hint)

            if self.has_user_feedback and event_id:
                feedback_script = self.FEEDBACK_JS % (self.dsn, json.dumps(dict(self.user_feedback, eventId=event_id)))

                if http_exception.has_body:
                    before, body_end, after = http_exception.text.partition('</body>')
                    if body_end:
                        http_exception.text = before + feedback_script + body_end + after
                else:
                    template = http_exception.body_template_obj.template
                    http_exception.body_template_obj = string.Template(template + feedback_script)

        return http_exception
