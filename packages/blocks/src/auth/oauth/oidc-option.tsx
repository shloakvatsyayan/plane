/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { KeyRound } from "lucide-react";
import type { IInstanceConfig, TOAuthOption } from "@plane/types";

type OIDCOptionProps = {
  config: Pick<IInstanceConfig, "is_oidc_enabled" | "oidc_provider_name"> | undefined;
  actionText: string;
  apiBaseUrl: string;
  nextPath: string | null;
  isSpace?: boolean;
};

export function getOIDCOption({
  config,
  actionText,
  apiBaseUrl,
  nextPath,
  isSpace = false,
}: OIDCOptionProps): TOAuthOption {
  return {
    id: "oidc",
    text: `${actionText} with ${config?.oidc_provider_name || "Single sign-on"}`,
    icon: <KeyRound size={18} aria-hidden="true" />,
    enabled: config?.is_oidc_enabled === true,
    onClick: () => {
      const query = nextPath ? `?${new URLSearchParams({ next_path: nextPath })}` : "";
      window.location.assign(`${apiBaseUrl}/auth/${isSpace ? "spaces/" : ""}oidc/${query}`);
    },
  };
}
