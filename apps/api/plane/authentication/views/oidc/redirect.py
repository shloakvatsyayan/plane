# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
from urllib.parse import urlencode

from django.http import HttpResponseRedirect

from plane.authentication.utils.host import base_host


def error_redirect(request, exc, is_space):
    logging.getLogger("plane.authentication").warning("OIDC login rejected: %s", exc.error_message)
    origin = base_host(request=request, is_app=not is_space, is_space=is_space)
    return HttpResponseRedirect(origin.rstrip("/") + "/?" + urlencode(exc.get_error_dict()))
