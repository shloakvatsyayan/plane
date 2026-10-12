# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import time

import jwt
import pytest

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oidc.tokens import verify_id_token

pytestmark = pytest.mark.unit


def test_accepts_signed_identity(oidc_config, oidc_claims, encode_token, jwks):
    claims = verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "access-token")
    assert claims["sub"] == "immutable-user-id"


@pytest.mark.parametrize(
    "claim, replacement",
    [
        ("iss", "https://attacker.example.com/"),
        ("aud", "another-client"),
        ("exp", 1),
        ("iat", int(time.time()) + 3600),
        ("nonce", "wrong-nonce"),
        ("nonce", True),
        ("sub", ""),
        ("sub", 123),
        ("azp", "another-client"),
        ("at_hash", "invalid"),
        ("aud", ["plane", "another-client"]),
    ],
)
def test_rejects_invalid_claims(claim, replacement, oidc_config, oidc_claims, encode_token, jwks):
    oidc_claims[claim] = replacement
    with pytest.raises(AuthenticationException):
        verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "access-token")


@pytest.mark.parametrize("claim", ["iss", "aud", "exp", "iat", "sub", "nonce"])
def test_requires_identity_claims(claim, oidc_config, oidc_claims, encode_token, jwks):
    del oidc_claims[claim]
    with pytest.raises(AuthenticationException):
        verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "access-token")


@pytest.mark.parametrize("algorithm", ["none", "HS256"])
def test_rejects_unsigned_and_symmetric_tokens(algorithm, oidc_config, oidc_claims, jwks):
    token = jwt.encode(
        oidc_claims, "" if algorithm == "none" else "attacker-secret-that-is-at-least-32-bytes", algorithm=algorithm
    )
    with pytest.raises(AuthenticationException):
        verify_id_token(token, jwks, oidc_config, "test-nonce", "access-token")


def test_rejects_signature_from_another_key(oidc_config, oidc_claims, jwks):
    from cryptography.hazmat.primitives.asymmetric import rsa

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(oidc_claims, attacker_key, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(AuthenticationException):
        verify_id_token(token, jwks, oidc_config, "test-nonce", "access-token")


def test_rejects_unknown_signing_key(oidc_config, oidc_claims, encode_token, jwks):
    jwks["keys"][0]["kid"] = "different-key"
    with pytest.raises(AuthenticationException):
        verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "access-token")


def test_accepts_multiple_audiences_with_matching_authorized_party(oidc_config, oidc_claims, encode_token, jwks):
    oidc_claims.update(aud=["plane", "another-client"], azp="plane")
    assert verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "token")["azp"] == "plane"


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "RS512"])
def test_accepts_signing_keys_without_optional_algorithm(algorithm, oidc_config, oidc_claims, jwks, signing_key):
    del jwks["keys"][0]["alg"]
    token = jwt.encode(oidc_claims, signing_key, algorithm=algorithm, headers={"kid": "test-key"})
    assert verify_id_token(token, jwks, oidc_config, "test-nonce", "access-token")["sub"] == oidc_claims["sub"]


@pytest.mark.parametrize("key_property, setting", [("use", "enc"), ("key_ops", ["encrypt"]), ("alg", "RS512")])
def test_rejects_keys_not_intended_for_token_verification(
    key_property, setting, oidc_config, oidc_claims, jwks, encode_token
):
    jwks["keys"][0][key_property] = setting
    with pytest.raises(AuthenticationException):
        verify_id_token(encode_token(oidc_claims), jwks, oidc_config, "test-nonce", "access-token")
