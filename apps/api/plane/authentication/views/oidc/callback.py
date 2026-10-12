# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.http import HttpResponseRedirect
from django.views import View

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.client import OIDCClient
from plane.authentication.provider.oidc.config import OIDCConfig
from plane.authentication.provider.oidc.errors import oidc_error
from plane.authentication.provider.oidc.identity import OIDCIdentity
from plane.authentication.provider.oidc.transaction import SESSION_KEY, consume_transaction
from plane.authentication.utils.host import base_host
from plane.authentication.utils.login import user_login
from plane.authentication.utils.redirection_path import get_redirection_path
from plane.authentication.utils.user_auth_workflow import post_user_auth_workflow
from plane.utils.path_validator import validate_next_path

from .redirect import error_redirect


class OIDCCallbackEndpoint(View):
    def get(self, request):
        is_space = request.session.get(SESSION_KEY, {}).get("is_space", False)
        try:
            config = OIDCConfig.load()
            transaction = consume_transaction(request, config)
            code = request.GET.get("code")
            if request.GET.get("error") or not code:
                raise oidc_error()
            if request.GET.get("iss", config.issuer) != config.issuer:
                raise oidc_error()
            claims = OIDCClient(config).authenticate(code, transaction)
            callback = None if is_space else post_user_auth_workflow
            user = OIDCIdentity(request, claims, callback=callback).authenticate()
            user_login(request=request, user=user, is_app=not is_space, is_space=is_space)
            next_path = transaction["next_path"]
            if not next_path and not is_space:
                next_path = "/" + get_redirection_path(user).lstrip("/")
            origin = base_host(request=request, is_app=not is_space, is_space=is_space)
            return HttpResponseRedirect(origin.rstrip("/") + (validate_next_path(next_path) or "/"))
        except AuthenticationException as exc:
            return error_redirect(request, exc, is_space)
