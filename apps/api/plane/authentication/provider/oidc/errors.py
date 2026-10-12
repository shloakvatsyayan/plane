# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from plane.authentication.adapter.error import AUTHENTICATION_ERROR_CODES, AuthenticationException


def oidc_error(code="OIDC_PROVIDER_ERROR"):
    return AuthenticationException(error_code=AUTHENTICATION_ERROR_CODES[code], error_message=code)
