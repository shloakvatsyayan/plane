# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.http import HttpResponseRedirect
from django.views import View

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.client import OIDCClient
from plane.authentication.provider.oidc.config import OIDCConfig
from plane.authentication.provider.oidc.errors import oidc_error
from plane.authentication.provider.oidc.transaction import start_transaction
from plane.authentication.rate_limit import authentication_throttle_allows
from plane.license.models import Instance

from .redirect import error_redirect


class OIDCInitiateEndpoint(View):
    is_space = False

    def get(self, request):
        try:
            if not authentication_throttle_allows(request):
                raise oidc_error("RATE_LIMIT_EXCEEDED")
            instance = Instance.objects.first()
            if instance is None or not instance.is_setup_done:
                raise oidc_error("INSTANCE_NOT_CONFIGURED")
            config = OIDCConfig.load()
            client = OIDCClient(config)
            transaction = start_transaction(request, config, self.is_space)
            return HttpResponseRedirect(client.authorization_url(transaction))
        except AuthenticationException as exc:
            return error_redirect(request, exc, self.is_space)
