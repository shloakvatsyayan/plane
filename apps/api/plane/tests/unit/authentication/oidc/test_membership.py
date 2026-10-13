# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import uuid

import pytest

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.identity import OIDCIdentity
from plane.db.models import Account, Project, ProjectMember, User, Workspace, WorkspaceMember

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture
def managed_workspace(monkeypatch):
    owner = User.objects.create(email="owner@example.com", username=uuid.uuid4().hex)
    workspace = Workspace.objects.create(name="Staff", slug="staff", owner=owner)
    Project.objects.create(name="Issues", identifier="STAFF", workspace=workspace)
    monkeypatch.setenv("OIDC_STAFF_WORKSPACE", workspace.slug)
    monkeypatch.setenv("ENABLE_SIGNUP", "0")
    return workspace


@pytest.mark.parametrize(
    "group,role",
    [
        ("clublantern-staff", 5),
        ("clublantern-developers", 20),
        ("clublantern-administrators", 20),
    ],
)
def test_verified_group_provisions_membership_with_public_signup_disabled(
    managed_workspace, oidc_request, oidc_claims, group, role
):
    oidc_claims["groups"] = [group]
    user = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert WorkspaceMember.objects.get(member=user).role == role
    assert ProjectMember.objects.get(member=user).role == role
    assert Project.objects.get(workspace=managed_workspace).guest_view_all_features


def test_group_demotion_removes_administrator_membership(managed_workspace, oidc_request, oidc_claims):
    oidc_claims["groups"] = ["clublantern-developers"]
    user = OIDCIdentity(oidc_request, oidc_claims).authenticate()
    oidc_claims["groups"] = ["clublantern-staff"]
    OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert WorkspaceMember.objects.get(member=user).role == 5
    assert ProjectMember.objects.get(member=user).role == 5
    assert Account.objects.get(user=user).metadata["staff_access"]["role"] == "staff"


@pytest.mark.parametrize("groups", [[], None, "clublantern-administrators", ["unrelated"]])
def test_unknown_or_malformed_groups_cannot_register(managed_workspace, oidc_request, oidc_claims, groups):
    oidc_claims["groups"] = groups
    with pytest.raises(AuthenticationException):
        OIDCIdentity(oidc_request, oidc_claims).authenticate()
    assert not User.objects.filter(email=oidc_claims["email"]).exists()
