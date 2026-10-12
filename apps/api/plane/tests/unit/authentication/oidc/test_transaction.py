# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import copy

import pytest
from django.http import QueryDict

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.transaction import SESSION_KEY, start_transaction, consume_transaction

pytestmark = pytest.mark.unit


def test_binds_callback_to_session_and_consumes_once(oidc_request, oidc_config):
    transaction = start_transaction(oidc_request, oidc_config, False)
    oidc_request.GET = QueryDict("state=" + transaction["state"])
    assert consume_transaction(oidc_request, oidc_config) == transaction
    assert SESSION_KEY not in oidc_request.session
    with pytest.raises(AuthenticationException):
        consume_transaction(oidc_request, oidc_config)


def test_rejects_concurrent_replay_with_stale_session(oidc_request, oidc_config):
    transaction = start_transaction(oidc_request, oidc_config, False)
    session = copy.deepcopy(oidc_request.session)
    oidc_request.GET = QueryDict("state=" + transaction["state"])
    consume_transaction(oidc_request, oidc_config)
    oidc_request.session = session
    with pytest.raises(AuthenticationException):
        consume_transaction(oidc_request, oidc_config)


@pytest.mark.parametrize("failure", ["missing", "mismatch", "expired", "configuration"])
def test_rejects_invalid_login_transaction(failure, oidc_request, oidc_config):
    transaction = start_transaction(oidc_request, oidc_config, False)
    oidc_request.GET = QueryDict("state=" + transaction["state"])
    if failure == "missing":
        oidc_request.GET = QueryDict("")
    elif failure == "mismatch":
        oidc_request.GET = QueryDict("state=another-browser")
    elif failure == "expired":
        transaction["created_at"] -= 601
    else:
        transaction["config"] = "previous-provider"
    with pytest.raises(AuthenticationException):
        consume_transaction(oidc_request, oidc_config)


def test_preserves_space_destination_and_clears_old_next_path(oidc_request, oidc_config):
    oidc_request.GET = QueryDict("next_path=%2Fpublished%3Fview%3Dlist%26sort%3Dname")
    transaction = start_transaction(oidc_request, oidc_config, True)
    assert transaction["is_space"] is True
    assert transaction["next_path"] == "/published?view=list&sort=name"
    oidc_request.GET = QueryDict("")
    assert start_transaction(oidc_request, oidc_config, False)["next_path"] == ""
