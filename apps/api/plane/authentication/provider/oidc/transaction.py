# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import secrets
import time

from django.core.cache import cache

from plane.utils.path_validator import validate_next_path

from .errors import oidc_error


TRANSACTION_TTL = 600
SESSION_KEY = "oidc_transaction"


def start_transaction(request, config, is_space):
    transaction = {
        "state": secrets.token_urlsafe(32),
        "nonce": secrets.token_urlsafe(32),
        "verifier": secrets.token_urlsafe(64),
        "created_at": time.time(),
        "config": config.fingerprint,
        "is_space": is_space,
        "next_path": validate_next_path(request.GET.get("next_path", "")),
    }
    request.session[SESSION_KEY] = transaction
    return transaction


def consume_transaction(request, config):
    transaction = request.session.pop(SESSION_KEY, None)
    state = request.GET.get("state", "")
    if not transaction or not state or not secrets.compare_digest(state.encode(), transaction["state"].encode()):
        raise oidc_error()
    if not 0 <= time.time() - transaction["created_at"] <= TRANSACTION_TTL:
        raise oidc_error()
    if transaction["config"] != config.fingerprint:
        raise oidc_error()
    if not cache.add("oidc:consumed:" + transaction["state"], True, timeout=TRANSACTION_TTL):
        raise oidc_error()
    return transaction
