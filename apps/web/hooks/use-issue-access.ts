/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { EUserPermissions, EUserPermissionsLevel } from "@plane/constants";
import type { TIssue } from "@plane/types";
import { useUser, useUserPermissions } from "@/hooks/store/user";

export function useIssueAccess() {
  const { data: currentUser } = useUser();
  const { allowPermissions } = useUserPermissions();

  const canManageIssues = (workspaceSlug?: string, projectId?: string) =>
    allowPermissions(
      [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      EUserPermissionsLevel.PROJECT,
      workspaceSlug,
      projectId
    );

  const canEditIssue = (workspaceSlug?: string, projectId?: string, issue?: TIssue) => {
    if (canManageIssues(workspaceSlug, projectId)) return true;
    if (!issue || !currentUser) return false;
    const isStaff = allowPermissions([EUserPermissions.GUEST], EUserPermissionsLevel.PROJECT, workspaceSlug, projectId);
    return isStaff && (issue.created_by === currentUser.id || issue.assignee_ids?.includes(currentUser.id));
  };

  return { canEditIssue, canManageIssues };
}
