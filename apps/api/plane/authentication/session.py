# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework.authentication import SessionAuthentication

from .staff_access import enforce_staff_access


class BaseSessionAuthentication(SessionAuthentication):
    def authenticate(self, request):
        authentication = super().authenticate(request)
        if authentication is not None:
            enforce_staff_access(request, authentication[0])
        return authentication

    # Disable csrf for the rest apis
    def enforce_csrf(self, request):
        return
