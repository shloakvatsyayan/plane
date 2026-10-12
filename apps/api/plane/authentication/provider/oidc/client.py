# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import base64
import hashlib
from urllib.parse import urlencode, quote_plus

from .config import validate_endpoint
from .errors import oidc_error
from .tokens import verify_id_token
from .transport import fetch_document


class OIDCClient:
    def __init__(self, config):
        self.config = config
        self.metadata = fetch_document(config.discovery_url)
        if self.metadata.get("issuer") != config.issuer:
            raise oidc_error()
        for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            validate_endpoint(self.metadata.get(endpoint))
        supported_methods = self.metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
        if not isinstance(supported_methods, list) or config.auth_method not in supported_methods:
            raise oidc_error("OIDC_NOT_CONFIGURED")
        pkce_methods = self.metadata.get("code_challenge_methods_supported", ["S256"])
        if not isinstance(pkce_methods, list) or "S256" not in pkce_methods:
            raise oidc_error("OIDC_NOT_CONFIGURED")

    def authorization_url(self, transaction):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(transaction["verifier"].encode()).digest()).rstrip(b"=")
        parameters = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": "openid profile email",
            "state": transaction["state"],
            "nonce": transaction["nonce"],
            "code_challenge": challenge.decode(),
            "code_challenge_method": "S256",
        }
        endpoint = self.metadata["authorization_endpoint"]
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(parameters)

    def authenticate(self, code, transaction):
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "code_verifier": transaction["verifier"],
        }
        headers = {"Accept": "application/json"}
        if self.config.auth_method == "client_secret_basic":
            credentials = (
                quote_plus(self.config.client_id, safe="") + ":" + quote_plus(self.config.client_secret, safe="")
            )
            headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
        else:
            form.update(client_id=self.config.client_id, client_secret=self.config.client_secret)
        tokens = fetch_document(self.metadata["token_endpoint"], method="POST", data=form, headers=headers)
        access_token = tokens.get("access_token")
        if (
            not isinstance(access_token, str)
            or not access_token
            or str(tokens.get("token_type", "")).lower() != "bearer"
        ):
            raise oidc_error()
        jwks = fetch_document(self.metadata["jwks_uri"])
        claims = verify_id_token(tokens.get("id_token"), jwks, self.config, transaction["nonce"], access_token)
        userinfo_endpoint = self.metadata.get("userinfo_endpoint")
        if userinfo_endpoint:
            user_claims = fetch_document(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
            if user_claims.get("sub") != claims["sub"]:
                raise oidc_error()
            if "email" in user_claims:
                claims["email"] = user_claims["email"]
                claims["email_verified"] = user_claims.get("email_verified")
            for claim in ("given_name", "family_name", "name", "preferred_username"):
                if claim in user_claims:
                    claims[claim] = user_claims[claim]
        if claims.get("email_verified") is not True:
            raise oidc_error("OAUTH_PROVIDER_UNVERIFIED_EMAIL")
        return claims
