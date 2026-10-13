# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.db.models import Q
from rest_framework.exceptions import PermissionDenied

from plane.db.models import Account, Issue, ProjectMember


def is_restricted_staff(user):
    return Account.objects.filter(user=user, provider="oidc", metadata__staff_access__role="staff").exists()


def can_edit_staff_issue(user, slug, project_id, issue_id=None):
    if not ProjectMember.objects.filter(
        member=user, project_id=project_id, workspace__slug=slug, is_active=True
    ).exists():
        return False
    if issue_id is None:
        return True
    return Issue.objects.filter(
        Q(created_by=user) | Q(assignees=user),
        pk=issue_id,
        project_id=project_id,
        workspace__slug=slug,
    ).exists()


def enforce_staff_access(request, user):
    if request.method in ("GET", "HEAD", "OPTIONS") or not is_restricted_staff(user):
        return
    route = request.resolver_match
    if route is None:
        raise PermissionDenied("Staff cannot perform this action.")
    if route.url_name in ("user-onboard", "user-tour") and request.method in ("POST", "PATCH"):
        return
    if route.url_name == "users" and request.path == "/api/users/me/" and request.method == "PATCH":
        return
    issue_routes = {
        "project-issue": {"POST", "PATCH"},
        "project-issue-comment": {"POST", "PATCH"},
        "project-issue-links": {"POST", "PATCH"},
        "project-issue-attachments": {"POST", "PATCH"},
    }
    if request.method not in issue_routes.get(route.url_name, set()):
        raise PermissionDenied("Staff can create and edit their issues but cannot delete content.")
    parameters = route.kwargs
    issue_id = parameters.get("issue_id")
    if route.url_name == "project-issue":
        issue_id = parameters.get("pk")
    if not can_edit_staff_issue(user, parameters.get("slug"), parameters.get("project_id"), issue_id):
        raise PermissionDenied("Staff can only edit issues they created or are assigned to.")
    if route.url_name == "project-issue":
        forbidden = {"archived_at", "deleted_at"}
        if forbidden.intersection(request.data) or request.data.get("parent_id") or request.data.get("parent"):
            raise PermissionDenied("Staff cannot move or archive issues.")
