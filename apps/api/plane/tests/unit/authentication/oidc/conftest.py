# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache
from django.test import RequestFactory

from plane.authentication.provider.oidc.config import OIDCConfig


@pytest.fixture
def oidc_config(monkeypatch):
    configuration = {
        "IS_OIDC_ENABLED": "1",
        "OIDC_ISSUER": "https://auth.example.com/application/o/plane/",
        "OIDC_CLIENT_ID": "plane",
        "OIDC_CLIENT_SECRET": "test-client-secret",
        "OIDC_REDIRECT_URI": "https://plane.example.com/auth/oidc/callback/",
        "OIDC_TOKEN_AUTH_METHOD": "client_secret_basic",
        "OIDC_DISCOVERY_URL": "",
    }
    for name, setting in configuration.items():
        monkeypatch.setenv(name, setting)
    return OIDCConfig.load()


@pytest.fixture
def oidc_claims(oidc_config):
    return {
        "iss": oidc_config.issuer,
        "sub": "immutable-user-id",
        "aud": oidc_config.client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": "test-nonce",
        "email": "member@example.com",
        "email_verified": True,
        "given_name": "Plane",
        "family_name": "Member",
    }


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks(signing_key):
    public_key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    return {"keys": [{**public_key, "kid": "test-key", "use": "sig", "alg": "RS256"}]}


@pytest.fixture
def encode_token(signing_key):
    return lambda claims: jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})


@pytest.fixture
def oidc_request(settings):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    cache.clear()
    request = RequestFactory().get("/auth/oidc/", HTTP_USER_AGENT="OIDC test browser")
    request.session = {}
    return request


@pytest.fixture
def metadata(oidc_config):
    return {
        "issuer": oidc_config.issuer,
        "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
        "token_endpoint": "https://auth.example.com/application/o/token/",
        "jwks_uri": "https://auth.example.com/application/o/plane/jwks/",
        "userinfo_endpoint": "https://auth.example.com/application/o/userinfo/",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }
