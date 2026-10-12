# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .errors import oidc_error


def validate_endpoint(endpoint, *, allow_localhost=False):
    if not isinstance(endpoint, str) or not endpoint or any(char.isspace() for char in endpoint):
        raise oidc_error("OIDC_NOT_CONFIGURED")
    try:
        parsed = urlsplit(endpoint)
        is_local = allow_localhost and parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or "\\" in endpoint
            or (parsed.scheme != "https" and not (is_local and parsed.scheme == "http"))
        ):
            raise ValueError
        parsed.port
    except ValueError:
        raise oidc_error("OIDC_NOT_CONFIGURED") from None
    return endpoint


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    discovery_url: str
    redirect_uri: str
    auth_method: str

    @classmethod
    def load(cls):
        if os.environ.get("IS_OIDC_ENABLED", "0") != "1":
            raise oidc_error("OIDC_NOT_CONFIGURED")
        issuer = validate_endpoint(os.environ.get("OIDC_ISSUER", ""))
        if urlsplit(issuer).query:
            raise oidc_error("OIDC_NOT_CONFIGURED")
        client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
        client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
        auth_method = os.environ.get("OIDC_TOKEN_AUTH_METHOD", "client_secret_basic")
        if not client_id or not client_secret or auth_method not in ("client_secret_basic", "client_secret_post"):
            raise oidc_error("OIDC_NOT_CONFIGURED")
        discovery_url = os.environ.get("OIDC_DISCOVERY_URL") or issuer.rstrip("/") + "/.well-known/openid-configuration"
        redirect_uri = validate_endpoint(os.environ.get("OIDC_REDIRECT_URI", ""), allow_localhost=True)
        if urlsplit(redirect_uri).query or not urlsplit(redirect_uri).path.endswith("/auth/oidc/callback/"):
            raise oidc_error("OIDC_NOT_CONFIGURED")
        return cls(issuer, client_id, client_secret, validate_endpoint(discovery_url), redirect_uri, auth_method)

    @property
    def fingerprint(self):
        configuration = [
            self.issuer,
            self.client_id,
            self.client_secret,
            self.discovery_url,
            self.redirect_uri,
            self.auth_method,
        ]
        return hashlib.sha256(json.dumps(configuration).encode()).hexdigest()


def public_oidc_config():
    return {
        "is_oidc_enabled": os.environ.get("IS_OIDC_ENABLED", "0") == "1",
        "oidc_provider_name": os.environ.get("OIDC_PROVIDER_NAME", "Single sign-on").strip() or "Single sign-on",
    }
