# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import uuid

import pytest
from django.utils import timezone

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.identity import OIDCIdentity
from plane.db.models import Account, Profile, User, Workspace, WorkspaceMemberInvite

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture(autouse=True)
def enable_signup(monkeypatch):
    monkeypatch.setenv("ENABLE_SIGNUP", "1")


def test_creates_user_and_binding_without_storing_tokens(oidc_request, oidc_claims):
    user = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    account = Account.objects.get(user=user, provider="oidc")
    assert account.metadata == {"issuer": oidc_claims["iss"], "subject": oidc_claims["sub"]}
    assert account.access_token == ""
    assert account.id_token == ""
    assert account.refresh_token is None
    assert user.last_login_medium == "oidc"
    assert user.is_email_verified
    assert user.is_password_autoset
    assert Profile.objects.filter(user=user).exists()


def test_links_existing_user_by_verified_email(oidc_request, oidc_claims):
    existing = User.objects.create(email=oidc_claims["email"], username=uuid.uuid4().hex)
    assert OIDCIdentity(oidc_request, oidc_claims).authenticate().pk == existing.pk
    assert User.objects.count() == 1


def test_returning_subject_keeps_identity_when_email_changes(oidc_request, oidc_claims):
    original = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    another = User.objects.create(email="another@example.com", username=uuid.uuid4().hex)
    oidc_claims["email"] = another.email
    returning = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert returning.pk == original.pk
    assert returning.email == original.email
    assert Account.objects.filter(provider="oidc").count() == 1


def test_rejects_reassigned_email_for_another_subject(oidc_request, oidc_claims):
    OIDCIdentity(oidc_request, oidc_claims).authenticate()
    oidc_claims["sub"] = "new-owner-of-same-email"
    with pytest.raises(AuthenticationException) as caught:
        OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert caught.value.error_message == "OIDC_ACCOUNT_CONFLICT"


@pytest.mark.parametrize("account_kind", ["bot", "deactivated"])
def test_preserves_account_restrictions(account_kind, oidc_request, oidc_claims):
    User.objects.create(
        email=oidc_claims["email"],
        username=uuid.uuid4().hex,
        is_bot=account_kind == "bot",
        is_active=account_kind != "deactivated",
        last_logout_time=timezone.now() if account_kind == "deactivated" else None,
    )
    with pytest.raises(AuthenticationException):
        OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert not Account.objects.exists()


def test_disabled_signup_does_not_create_user(oidc_request, oidc_claims, monkeypatch):
    monkeypatch.setenv("ENABLE_SIGNUP", "0")
    with pytest.raises(AuthenticationException) as caught:
        OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert caught.value.error_message == "SIGNUP_DISABLED"
    assert not User.objects.exists()


def test_invitation_allows_signup_when_public_signup_disabled(oidc_request, oidc_claims, monkeypatch):
    monkeypatch.setenv("ENABLE_SIGNUP", "0")
    owner = User.objects.create(email="owner@example.com", username=uuid.uuid4().hex)
    workspace = Workspace.objects.create(name="Invited", slug="invited", owner=owner)
    WorkspaceMemberInvite.objects.create(workspace=workspace, email=oidc_claims["email"], token="invite-token")
    assert OIDCIdentity(oidc_request, oidc_claims).authenticate().email == oidc_claims["email"]


def test_binding_failure_rolls_back_new_account(oidc_request, oidc_claims, mocker):
    from django.db import IntegrityError

    mocker.patch("plane.authentication.provider.oidc.identity.Account.objects.create", side_effect=IntegrityError)
    with pytest.raises(AuthenticationException):
        OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert not User.objects.exists()
    assert not Profile.objects.exists()


def test_login_without_user_agent_uses_empty_string(oidc_request, oidc_claims):
    oidc_request.META.pop("HTTP_USER_AGENT")
    user = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert user.last_login_uagent == ""
