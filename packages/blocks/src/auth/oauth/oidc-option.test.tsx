/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { getOIDCOption } from "./oidc-option";

const configuration = { is_oidc_enabled: true, oidc_provider_name: "authentik" };

afterEach(() => vi.unstubAllGlobals());

describe("OIDC sign-in option", () => {
  it("stays hidden until the instance enables OIDC", () => {
    const option = getOIDCOption({ config: undefined, actionText: "Sign in", apiBaseUrl: "", nextPath: null });
    expect(option.enabled).toBe(false);
  });

  it("uses the configured provider name", () => {
    const option = getOIDCOption({ config: configuration, actionText: "Sign in", apiBaseUrl: "", nextPath: null });
    expect(option.text).toBe("Sign in with authentik");
    expect(option.enabled).toBe(true);
  });

  it.each([false, true])("preserves the full return path for isSpace=%s", (isSpace) => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { assign } });
    const nextPath = "/workspace?view=list&sort=name";
    const option = getOIDCOption({
      config: configuration,
      actionText: "Sign in",
      apiBaseUrl: "https://plane.example.com",
      nextPath,
      isSpace,
    });
    option.onClick();
    const destination = new URL(assign.mock.calls[0][0]);
    expect(destination.pathname).toBe(isSpace ? "/auth/spaces/oidc/" : "/auth/oidc/");
    expect(destination.searchParams.get("next_path")).toBe(nextPath);
    expect([...destination.searchParams.keys()]).toEqual(["next_path"]);
  });
});
