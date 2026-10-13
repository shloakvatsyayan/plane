# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from types import SimpleNamespace
from uuid import uuid4

import pytest
from django.urls import resolve
from rest_framework.exceptions import PermissionDenied

from plane.authentication.staff_access import enforce_staff_access
from plane.db.models import Account, Issue, Project, ProjectMember, User, Workspace, WorkspaceMember

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture
def staff_scope(settings, mocker):
    settings.WEB_URL = "https://issues.example.com"
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    mocker.patch("celery.app.task.Task.apply_async")
    staff = User.objects.create(email="staff@example.com", username=uuid4().hex)
    colleague = User.objects.create(email="colleague@example.com", username=uuid4().hex)
    workspace = Workspace.objects.create(name="Staff", slug="staff", owner=colleague)
    project = Project.objects.create(name="Issues", identifier="STAFF", workspace=workspace)
    WorkspaceMember.objects.create(workspace=workspace, member=staff, role=5)
    ProjectMember.objects.create(project=project, workspace=workspace, member=staff, role=5)
    Account.objects.create(
        user=staff,
        provider="oidc",
        provider_account_id="staff",
        access_token="",
        metadata={"staff_access": {"role": "staff", "workspace": "staff"}},
    )
    own = Issue.objects.create(name="Own", project=project, workspace=workspace, created_by=staff)
    assigned = Issue.objects.create(name="Assigned", project=project, workspace=workspace, created_by=colleague)
    assigned.assignees.add(staff, through_defaults={"project": project, "workspace": workspace})
    other = Issue.objects.create(name="Other", project=project, workspace=workspace, created_by=colleague)
    Issue.objects.filter(pk=own.pk).update(created_by=staff)
    Issue.objects.filter(pk__in=[assigned.pk, other.pk]).update(created_by=colleague)
    return staff, project, own, assigned, other


def request_for(project, suffix="", method="PATCH", payload=None):
    path = f"/api/workspaces/staff/projects/{project.pk}/issues/{suffix}"
    return SimpleNamespace(method=method, path=path, data=payload or {}, resolver_match=resolve(path))


def test_staff_can_create_and_edit_created_or_assigned_issues(staff_scope):
    staff, project, own, assigned, _ = staff_scope
    enforce_staff_access(request_for(project, method="POST"), staff)
    for issue in (own, assigned):
        enforce_staff_access(request_for(project, f"{issue.pk}/"), staff)


def test_staff_cannot_edit_other_issues_or_grant_themselves_assignment(staff_scope):
    staff, project, _, _, other = staff_scope
    with pytest.raises(PermissionDenied):
        enforce_staff_access(request_for(project, f"{other.pk}/", payload={"assignee_ids": [str(staff.pk)]}), staff)


@pytest.mark.parametrize(
    "suffix,method,payload",
    [
        ("own", "DELETE", {}),
        ("own", "PATCH", {"archived_at": "2026-10-13"}),
        ("own", "PATCH", {"deleted_at": "2026-10-13"}),
    ],
)
def test_staff_cannot_delete_or_soft_delete_their_issues(staff_scope, suffix, method, payload):
    staff, project, own, _, _ = staff_scope
    with pytest.raises(PermissionDenied):
        enforce_staff_access(request_for(project, f"{own.pk}/", method, payload), staff)


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/workspaces/", "POST"),
        ("/api/users/me/api-tokens/", "POST"),
    ],
)
def test_staff_cannot_gain_access_through_unlisted_write_routes(staff_scope, path, method):
    staff, _, _, _, _ = staff_scope
    with pytest.raises(PermissionDenied):
        enforce_staff_access(SimpleNamespace(method=method, path=path, data={}, resolver_match=None), staff)


def test_elevated_identity_keeps_full_access(staff_scope):
    staff, project, own, _, _ = staff_scope
    Account.objects.filter(user=staff).update(metadata={"staff_access": {"role": "administrator"}})
    enforce_staff_access(request_for(project, f"{own.pk}/", "DELETE"), staff)


def test_revoked_project_membership_cannot_edit_existing_issue(staff_scope):
    staff, project, own, _, _ = staff_scope
    ProjectMember.objects.filter(member=staff).update(is_active=False)
    with pytest.raises(PermissionDenied):
        enforce_staff_access(request_for(project, f"{own.pk}/"), staff)


def test_session_api_enforces_ownership_and_denies_deletion(staff_scope):
    from rest_framework.test import APIClient

    staff, project, own, assigned, other = staff_scope
    client = APIClient()
    client.force_login(staff)
    prefix = f"/api/workspaces/staff/projects/{project.pk}/issues/"
    assert client.post(prefix, {"name": "Staff report"}, format="json").status_code == 201
    for issue in (own, assigned):
        assert client.patch(f"{prefix}{issue.pk}/", {"name": "Updated"}, format="json").status_code == 204
        issue.refresh_from_db()
        assert issue.name == "Updated"
        assert client.delete(f"{prefix}{issue.pk}/").status_code == 403
    assert client.patch(f"{prefix}{other.pk}/", {"name": "Forbidden"}, format="json").status_code == 403
