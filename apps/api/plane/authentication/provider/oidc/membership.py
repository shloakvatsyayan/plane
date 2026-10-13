# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os

from plane.db.models import Profile, Project, ProjectMember, Workspace, WorkspaceMember

from .errors import oidc_error


def staff_access(claims):
    workspace_slug = os.environ.get("OIDC_STAFF_WORKSPACE", "")
    if not workspace_slug:
        return None
    groups = claims.get("groups")
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise oidc_error()
    if any(group in groups for group in ("clublantern-administrators", "clublantern-developers")):
        role = "administrator"
    elif "clublantern-staff" in groups:
        role = "staff"
    else:
        raise oidc_error()
    if not Workspace.objects.filter(slug=workspace_slug).exists():
        raise oidc_error("OIDC_NOT_CONFIGURED")
    return {"workspace": workspace_slug, "role": role}


def sync_membership(user, access):
    if access is None:
        return
    workspace = Workspace.objects.get(slug=access["workspace"])
    Profile.objects.filter(user=user).update(is_onboarded=True, last_workspace_id=workspace.pk)
    role = 5 if access["role"] == "staff" else 20
    WorkspaceMember.objects.update_or_create(
        workspace=workspace, member=user, defaults={"role": role, "is_active": True}
    )
    for project in Project.objects.filter(workspace=workspace):
        ProjectMember.objects.update_or_create(
            project=project,
            member=user,
            defaults={"workspace": workspace, "role": role, "is_active": True},
        )
    Project.objects.filter(workspace=workspace, guest_view_all_features=False).update(guest_view_all_features=True)
