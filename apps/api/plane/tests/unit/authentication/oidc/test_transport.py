# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import pytest
import requests

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.transport import fetch_document

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "status, body", [(302, b"{}"), (500, b"{}"), (200, b"not-json"), (200, b"[]"), (200, b"x" * 1048577)]
)
def test_rejects_redirects_errors_and_malformed_documents(status, body, mocker):
    response = mocker.MagicMock(status_code=status)
    response.iter_content.return_value = [body]
    request = mocker.patch("plane.authentication.provider.oidc.transport.requests.request")
    request.return_value.__enter__.return_value = response
    with pytest.raises(AuthenticationException):
        fetch_document("https://auth.example.com/discovery")
    assert request.call_args.kwargs["allow_redirects"] is False
    assert request.call_args.kwargs["timeout"] == (5, 15)


def test_provider_timeout_becomes_authentication_failure(mocker):
    mocker.patch("plane.authentication.provider.oidc.transport.requests.request", side_effect=requests.Timeout)
    with pytest.raises(AuthenticationException):
        fetch_document("https://auth.example.com/discovery")
