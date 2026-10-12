# OpenID Connect sign-in

This fork supports one configurable OpenID Connect provider for the main app and published sites. It uses authorization code flow with S256 PKCE, discovery, signed ID tokens and the existing Plane session and invitation workflows. authentik is the primary configuration example; other providers must support the same protocol and return a verified email.

## Configure authentik

1. Create an OAuth2/OpenID Provider and an application with slug `plane`.
2. Select a **confidential** client and copy its client ID and secret.
3. Add the strict redirect URI `https://plane.example.com/auth/oidc/callback/`. Both the main app and published sites use this callback.
4. Select an asymmetric signing key, such as authentik's RSA signing certificate. Unsigned and HMAC-signed ID tokens are rejected.
5. Keep the default per-provider issuer mode. Copy the exact issuer from discovery, including its trailing slash: typically `https://auth.example.com/application/o/plane/`.
6. Include the `openid`, `profile` and `email` scope mappings. Ensure the user has a verified email and the provider returns the JSON boolean `email_verified: true`. Recent authentik versions default this claim to false until verification is configured. Follow authentik's [email verification guide](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/verify-email-address/); do not mark arbitrary, user-supplied email addresses as verified.
7. Bind the application to the users/groups allowed to access Plane. For a staff-only deployment, enforce membership and MFA in authentik's application policies and authentication flow.

## Configure Plane

Set these variables on the **API service**, then restart it:

```dotenv
IS_OIDC_ENABLED=1
OIDC_PROVIDER_NAME=authentik
OIDC_ISSUER=https://auth.example.com/application/o/plane/
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://plane.example.com/auth/oidc/callback/
OIDC_TOKEN_AUTH_METHOD=client_secret_basic
```

`OIDC_DISCOVERY_URL` is optional. It defaults to the issuer without a trailing slash plus `/.well-known/openid-configuration`. Set it explicitly for providers whose discovery endpoint differs, including authentik's global issuer mode. The discovery document's issuer must exactly match `OIDC_ISSUER`.

`OIDC_TOKEN_AUTH_METHOD` accepts `client_secret_basic` (default) or `client_secret_post`. Use a method advertised by the provider. The requested scopes are `openid profile email`; refresh tokens are not needed for Plane sessions.

The provider name is shown in the existing sign-in and sign-up buttons. These settings are environment-managed, independent of `SKIP_ENV_VAR`; the God Mode authentication page does not edit them. The public instance endpoint exposes only the enabled flag and display name. Its existing cache can delay a button change by up to two hours; the authentication endpoints enforce the current environment immediately.

For Docker Compose, add the variables to the API service's `env_file` or `environment`. The local test/development stack uses `apps/api/.env`; adding variables only to Compose's root `.env` does not inject them into containers. Existing deployments must run the normal API migrations, including `0123_account_oidc_provider`.

Set `OIDC_REDIRECT_URI` to the browser-reachable **API** callback, not an internal container address. Behind Plane's standard proxy, this is the same public origin as the app. For local development, `http://localhost:8000/auth/oidc/callback/` is allowed. Provider discovery, token, userinfo and JWKS endpoints always require HTTPS with valid certificates. Private IdP addresses are allowed because the provider is trusted operator configuration; no endpoint URL comes from a login request. Configure `REQUESTS_CA_BUNDLE` for a private CA instead of disabling verification.

The backend must reach the discovery, token, JWKS and userinfo endpoints without an interactive proxy challenge. Published sites initiate at `/auth/spaces/oidc/`; the callback restores the saved site destination. When using different app/site/API subdomains, configure Plane's shared `COOKIE_DOMAIN` and HTTPS origins so the session cookie reaches all of them.

## Account behavior

- The first login links an existing Plane account by its verified email, or creates a new account if signups/invitations permit. Enabling this provider therefore trusts it to attest ownership of existing account emails.
- Returning logins use the issuer and immutable subject. Changing the IdP email does not change the Plane account email or switch to another account.
- A different subject cannot claim an email already linked to this issuer. Recreating IdP users or changing subject mappings requires an intentional account-binding migration.
- Bots and explicitly deactivated accounts cannot sign in. Existing signup restrictions and workspace invitations still apply.
- Tokens and client secrets are never saved in account records or browser storage. The account binding contains issuer and subject; access and ID tokens are discarded after login.
- Login transactions expire after ten minutes and can be consumed only once. Starting another OIDC login in the same browser replaces the pending transaction.
- Plane logout ends the Plane session. IdP logout, back-channel logout, role/group synchronization, SCIM and God Mode SSO are not implemented. Removing IdP access prevents future OIDC logins; it does not revoke an existing Plane session.

To require SSO, configure existing email/password and magic-code switches separately in God Mode after verifying OIDC works. Restrict signup/workspace creation as appropriate; OIDC does not change these policies or grant administrator roles.

## Verify a deployment

Sign in with an authorized authentik user, confirm the expected account and workspace, then sign out and repeat. Verify an unauthorized authentik user is denied by application policy, an unverified email is rejected, and a deactivated Plane account stays blocked. Check the published-site flow if used.

The automated suite covers signed-token validation, PKCE parameters, state/nonce/replay protection, provider errors, verified emails, stable account linking, signup restrictions, redirects and session creation. A successful local test run does not establish connectivity to your authentik instance.

Protocol reference: [authentik OAuth2/OIDC provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/). The older [bitbay/plane-oidc fork](https://github.com/bitbay/plane-oidc) was reviewed as a reference; this implementation uses the current fork's authentication model and existing dependencies.
