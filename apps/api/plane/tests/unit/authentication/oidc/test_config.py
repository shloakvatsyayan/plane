# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import pytest

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.config import OIDCConfig, public_oidc_config

pytestmark = pytest.mark.unit


def test_uses_authentik_discovery_path(oidc_config):
    assert oidc_config.discovery_url == "https://auth.example.com/application/o/plane/.well-known/openid-configuration"


@pytest.mark.parametrize(
    "name, setting",
    [
        ("IS_OIDC_ENABLED", "0"),
        ("OIDC_ISSUER", "http://auth.example.com/"),
        ("OIDC_ISSUER", "https://auth.example.com/?query=1"),
        ("OIDC_CLIENT_ID", ""),
        ("OIDC_CLIENT_SECRET", ""),
        ("OIDC_TOKEN_AUTH_METHOD", "none"),
        ("OIDC_REDIRECT_URI", "http://plane.example.com/auth/oidc/callback/"),
        ("OIDC_REDIRECT_URI", "https://plane.example.com/wrong/callback/"),
        ("OIDC_DISCOVERY_URL", "https://user:password@auth.example.com/"),
        ("OIDC_DISCOVERY_URL", "https://auth.example.com/#fragment"),
    ],
)
def test_rejects_unsafe_or_incomplete_configuration(name, setting, oidc_config, monkeypatch):
    monkeypatch.setenv(name, setting)
    with pytest.raises(AuthenticationException):
        OIDCConfig.load()


def test_allows_loopback_callback_for_local_development(oidc_config, monkeypatch):
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback/")
    assert OIDCConfig.load().redirect_uri.startswith("http://localhost:")


def test_public_configuration_never_contains_credentials(oidc_config):
    assert set(public_oidc_config()) == {"is_oidc_enabled", "oidc_provider_name"}
    assert oidc_config.client_secret not in repr(oidc_config)
