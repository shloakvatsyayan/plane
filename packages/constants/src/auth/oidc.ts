/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

export const OIDC_ERROR_MESSAGES = {
  "5124": {
    title: "Email not verified",
    message: () => "Verify your email with your identity provider, then try again.",
  },
  "5200": {
    title: "Single sign-on unavailable",
    message: () => "Your administrator needs to configure single sign-on.",
  },
  "5201": {
    title: "Single sign-on failed",
    message: () => "Start sign-in again. If it keeps failing, contact your administrator.",
  },
  "5202": {
    title: "Account already linked",
    message: () => "This account is linked to a different identity. Contact your administrator.",
  },
};
