# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import base64
import hashlib
import secrets

import jwt

from .errors import oidc_error


SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")


def verify_id_token(encoded_token, jwks, config, nonce, access_token):
    try:
        header = jwt.get_unverified_header(encoded_token)
        algorithm = header.get("alg")
        if algorithm not in SIGNING_ALGORITHMS:
            raise oidc_error()
        public_keys = jwks.get("keys")
        if not isinstance(public_keys, list):
            raise oidc_error()
        signing_keys = [
            public_key
            for public_key in public_keys
            if isinstance(public_key, dict)
            and public_key.get("use") in (None, "sig")
            and public_key.get("alg") in (None, algorithm)
            and "verify" in public_key.get("key_ops", ["verify"])
            and (not header.get("kid") or public_key.get("kid") == header["kid"])
        ]
        if len(signing_keys) != 1:
            raise oidc_error()
        claims = jwt.decode(
            encoded_token,
            jwt.PyJWK.from_dict(signing_keys[0], algorithm=algorithm).key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=config.issuer,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        )
        if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 255:
            raise oidc_error()
        if not isinstance(claims["nonce"], str) or not secrets.compare_digest(claims["nonce"], nonce):
            raise oidc_error()
        audience = claims["aud"]
        if (isinstance(audience, list) and len(audience) > 1) or "azp" in claims:
            if claims.get("azp") != config.client_id:
                raise oidc_error()
        if "at_hash" in claims:
            digest = hashlib.new("sha" + algorithm[-3:], access_token.encode("ascii")).digest()
            expected_hash = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()
            if not isinstance(claims["at_hash"], str) or not secrets.compare_digest(claims["at_hash"], expected_hash):
                raise oidc_error()
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, UnicodeError):
        raise oidc_error() from None
