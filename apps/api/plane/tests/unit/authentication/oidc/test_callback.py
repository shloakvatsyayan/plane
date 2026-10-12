# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from django.core.cache import cache
from django.test import Client
from django.utils import timezone

from plane.authentication.provider.oidc.transaction import SESSION_KEY
from plane.db.models import Account, User
from plane.license.models import Instance

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture
def browser(settings, oidc_config, monkeypatch):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    settings.WEB_URL = "https://plane.example.com"
    settings.APP_BASE_URL = "https://plane.example.com"
    settings.SPACE_BASE_URL = "https://plane.example.com"
    settings.SPACE_BASE_PATH = "/spaces"
    monkeypatch.setenv("ENABLE_SIGNUP", "1")
    cache.clear()
    Instance.objects.create(
        instance_name="OIDC tests", instance_id=uuid.uuid4().hex, is_setup_done=True, last_checked_at=timezone.now()
    )
    return Client(HTTP_USER_AGENT="OIDC test browser")


@pytest.fixture
def provider_fetch(mocker, metadata):
    return mocker.patch("plane.authentication.provider.oidc.client.fetch_document", return_value=metadata)


@pytest.mark.parametrize("is_space", [False, True])
def test_signed_callback_logs_in_and_returns_to_requested_page(
    is_space,
    browser,
    provider_fetch,
    metadata,
    oidc_claims,
    jwks,
    encode_token,
):
    path = "/auth/spaces/oidc/" if is_space else "/auth/oidc/"
    initiation = browser.get(path, {"next_path": "/workspace?view=list&sort=name"})
    assert initiation.status_code == 302
    query = parse_qs(urlsplit(initiation.url).query)
    oidc_claims["nonce"] = query["nonce"][0]
    tokens = {"id_token": encode_token(oidc_claims), "access_token": "access-token", "token_type": "Bearer"}
    provider_fetch.side_effect = [metadata, tokens, jwks, oidc_claims]
    callback = browser.get("/auth/oidc/callback/", {"code": "authorization-code", "state": query["state"][0]})
    prefix = "https://plane.example.com/spaces" if is_space else "https://plane.example.com"
    assert callback.url == prefix + "/workspace?view=list&sort=name"
    user = User.objects.get(email=oidc_claims["email"])
    assert browser.session["_auth_user_id"] == str(user.pk)
    assert SESSION_KEY not in browser.session
    assert Account.objects.get(user=user).metadata["subject"] == oidc_claims["sub"]


@pytest.mark.parametrize("query", [{}, {"code": "code"}, {"code": "code", "state": "wrong"}, {"state": "é"}])
def test_invalid_callback_cannot_create_a_session(query, browser, provider_fetch):
    browser.get("/auth/oidc/")
    provider_fetch.reset_mock()
    callback = browser.get("/auth/oidc/callback/", query)
    assert "error_code=5201" in callback.url
    assert "_auth_user_id" not in browser.session
    assert not User.objects.exists()
    provider_fetch.assert_not_called()


def test_provider_denial_consumes_transaction(browser, provider_fetch):
    initiation = browser.get("/auth/oidc/")
    state = parse_qs(urlsplit(initiation.url).query)["state"][0]
    callback = browser.get("/auth/oidc/callback/", {"error": "access_denied", "state": state})
    assert "error_code=5201" in callback.url
    assert SESSION_KEY not in browser.session
    assert not User.objects.exists()


def test_disabled_provider_rejects_direct_initiation(browser, provider_fetch, monkeypatch):
    monkeypatch.setenv("IS_OIDC_ENABLED", "0")
    initiation = browser.get("/auth/oidc/")
    assert "error_code=5200" in initiation.url
    provider_fetch.assert_not_called()


def test_requires_completed_instance_setup(browser, provider_fetch):
    Instance.objects.update(is_setup_done=False)
    initiation = browser.get("/auth/oidc/")
    assert "error_code=5000" in initiation.url
    provider_fetch.assert_not_called()
