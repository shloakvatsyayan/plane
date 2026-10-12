# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.client import OIDCClient

pytestmark = pytest.mark.unit


def test_authorization_uses_nonce_and_pkce(oidc_config, metadata, mocker):
    mocker.patch("plane.authentication.provider.oidc.client.fetch_document", return_value=metadata)
    transaction = {"verifier": "verifier", "nonce": "nonce", "state": "state"}
    query = parse_qs(urlsplit(OIDCClient(oidc_config).authorization_url(transaction)).query)
    assert query["scope"] == ["openid profile email"]
    assert query["response_type"] == ["code"]
    assert query["nonce"] == ["nonce"]
    assert query["state"] == ["state"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [
        base64.urlsafe_b64encode(hashlib.sha256(b"verifier").digest()).rstrip(b"=").decode()
    ]


@pytest.mark.parametrize("failure", ["issuer", "endpoint", "auth_method"])
def test_rejects_untrusted_discovery(failure, oidc_config, metadata, mocker):
    if failure == "issuer":
        metadata["issuer"] = "https://attacker.example.com/"
    elif failure == "endpoint":
        metadata["token_endpoint"] = "http://auth.example.com/token"
    else:
        metadata["token_endpoint_auth_methods_supported"] = ["none"]
    mocker.patch("plane.authentication.provider.oidc.client.fetch_document", return_value=metadata)
    with pytest.raises(AuthenticationException):
        OIDCClient(oidc_config)


@pytest.mark.parametrize("verification", [True, False, "true", None])
def test_requires_boolean_verified_email(verification, oidc_config, metadata, oidc_claims, jwks, encode_token, mocker):
    user_claims = {"sub": oidc_claims["sub"], "email": oidc_claims["email"], "email_verified": verification}
    tokens = {"id_token": encode_token(oidc_claims), "access_token": "access-token", "token_type": "Bearer"}
    fetch = mocker.patch(
        "plane.authentication.provider.oidc.client.fetch_document", side_effect=[metadata, tokens, jwks, user_claims]
    )
    client = OIDCClient(oidc_config)
    transaction = {"nonce": "test-nonce", "verifier": "verifier"}
    if verification is True:
        assert client.authenticate("code", transaction)["email_verified"] is True
        assert fetch.call_args_list[1].kwargs["data"]["code_verifier"] == "verifier"
        assert fetch.call_args_list[1].kwargs["headers"]["Authorization"].startswith("Basic ")
    else:
        with pytest.raises(AuthenticationException) as caught:
            client.authenticate("code", transaction)
        assert caught.value.error_message == "OAUTH_PROVIDER_UNVERIFIED_EMAIL"


def test_rejects_userinfo_for_another_subject(oidc_config, metadata, oidc_claims, jwks, encode_token, mocker):
    tokens = {"id_token": encode_token(oidc_claims), "access_token": "access-token", "token_type": "Bearer"}
    mocker.patch(
        "plane.authentication.provider.oidc.client.fetch_document",
        side_effect=[
            metadata,
            tokens,
            jwks,
            {**oidc_claims, "sub": "another-subject"},
        ],
    )
    with pytest.raises(AuthenticationException):
        OIDCClient(oidc_config).authenticate("code", {"nonce": "test-nonce", "verifier": "verifier"})


def test_supports_post_client_credentials_and_id_token_only_claims(
    oidc_config,
    metadata,
    oidc_claims,
    jwks,
    encode_token,
    mocker,
):
    from dataclasses import replace

    config = replace(oidc_config, auth_method="client_secret_post")
    del metadata["userinfo_endpoint"]
    tokens = {"id_token": encode_token(oidc_claims), "access_token": "access-token", "token_type": "Bearer"}
    fetch = mocker.patch(
        "plane.authentication.provider.oidc.client.fetch_document", side_effect=[metadata, tokens, jwks]
    )
    claims = OIDCClient(config).authenticate("code", {"nonce": "test-nonce", "verifier": "verifier"})
    assert claims["email"] == oidc_claims["email"]
    form = fetch.call_args_list[1].kwargs["data"]
    assert form["client_id"] == config.client_id
    assert form["client_secret"] == config.client_secret
    assert "Authorization" not in fetch.call_args_list[1].kwargs["headers"]


def test_userinfo_email_cannot_inherit_id_token_verification(
    oidc_config,
    metadata,
    oidc_claims,
    jwks,
    encode_token,
    mocker,
):
    tokens = {"id_token": encode_token(oidc_claims), "access_token": "access-token", "token_type": "Bearer"}
    mocker.patch(
        "plane.authentication.provider.oidc.client.fetch_document",
        side_effect=[
            metadata,
            tokens,
            jwks,
            {"sub": oidc_claims["sub"], "email": "different@example.com"},
        ],
    )
    with pytest.raises(AuthenticationException) as caught:
        OIDCClient(oidc_config).authenticate("code", {"nonce": "test-nonce", "verifier": "verifier"})
    assert caught.value.error_message == "OAUTH_PROVIDER_UNVERIFIED_EMAIL"
