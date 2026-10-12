# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import json

from django.db import IntegrityError, transaction
from django.utils import timezone

from plane.authentication.adapter.base import Adapter
from plane.db.models import Account, User

from .errors import oidc_error


class OIDCIdentity(Adapter):
    def __init__(self, request, claims, callback=None):
        super().__init__(request=request, provider="oidc", callback=callback)
        if claims.get("email_verified") is not True:
            raise oidc_error("OAUTH_PROVIDER_UNVERIFIED_EMAIL")
        self.issuer = claims["iss"]
        self.subject = claims["sub"]
        self.account_id = hashlib.sha256(json.dumps([self.issuer, self.subject]).encode()).hexdigest()
        email = claims.get("email")
        if not isinstance(email, str):
            raise oidc_error("INVALID_EMAIL")
        self.user_data = {
            "email": self.sanitize_email(email),
            "user": {
                "first_name": self.profile_claim(claims, "given_name"),
                "last_name": self.profile_claim(claims, "family_name"),
                "is_password_autoset": True,
            },
        }

    @staticmethod
    def profile_claim(claims, name):
        claim = claims.get(name, "")
        if not isinstance(claim, str):
            raise oidc_error()
        return claim[:255]

    def authenticate(self):
        try:
            with transaction.atomic():
                account = (
                    Account.objects.select_for_update()
                    .filter(provider="oidc", provider_account_id=self.account_id)
                    .first()
                )
                if account:
                    user = User.objects.select_for_update().get(pk=account.user_id)
                    self.user_data["email"] = user.email
                else:
                    user = User.objects.select_for_update().filter(email=self.user_data["email"]).first()
                    if (
                        user
                        and Account.objects.filter(user=user, provider="oidc", metadata__issuer=self.issuer).exists()
                    ):
                        raise oidc_error("OIDC_ACCOUNT_CONFLICT")
                user = self.complete_login_or_signup()
                if account:
                    account.last_connected_at = timezone.now()
                    account.save(update_fields=["last_connected_at", "updated_at"])
                else:
                    Account.objects.create(
                        user=user,
                        provider="oidc",
                        provider_account_id=self.account_id,
                        access_token="",
                        metadata={"issuer": self.issuer, "subject": self.subject},
                    )
                return user
        except IntegrityError:
            raise oidc_error("OIDC_ACCOUNT_CONFLICT") from None
