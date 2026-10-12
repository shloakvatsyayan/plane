# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import json

import requests

from .config import validate_endpoint
from .errors import oidc_error


def fetch_document(endpoint, *, method="GET", **kwargs):
    validate_endpoint(endpoint)
    try:
        with requests.request(
            method, endpoint, timeout=(5, 15), allow_redirects=False, stream=True, **kwargs
        ) as response:
            if response.status_code != 200:
                raise oidc_error()
            chunks = []
            byte_count = 0
            for chunk in response.iter_content(chunk_size=16384):
                byte_count += len(chunk)
                if byte_count > 1024 * 1024:
                    raise oidc_error()
                chunks.append(chunk)
            document = json.loads(b"".join(chunks))
            if not isinstance(document, dict):
                raise oidc_error()
            return document
    except (requests.RequestException, ValueError):
        raise oidc_error() from None
