# Staff Login Flow with Keycloak (UI + Backend API)

## Purpose

This document explains, in detail, what happens when a staff user logs in with Keycloak in the current OpenG2P IAM setup.

It covers:

- UI steps
- Backend API calls
- IAM core service flow
- Keycloak interactions
- Token/cookie behavior
- Protected API usage after login

---

## Components

- Staff UI (browser frontend)
- Staff Portal API (`iam-staff-portal-api`)
- IAM Core Auth Service (`iam-core/src/iam_core/services/auth_service.py`)
- Keycloak (OIDC provider)

---

## End-to-end sequence

```mermaid
sequenceDiagram
  autonumber
  participant U as Staff User
  participant UI as Staff UI
  participant API as Staff Portal API
  participant Core as AuthService
  participant KC as Keycloak

  U->>UI: Open login page
  UI->>API: GET /auth/get_login_providers
  API->>Core: get_login_providers(user_type="staff")
  Core-->>API: staff login provider list
  API-->>UI: provider list (id, name, icon, label)

  U->>UI: Click "Login with Keycloak"
  UI->>API: POST /auth/start_authentication_transaction?id={providerId}&redirect_uri={uiReturn}
  API->>Core: start_authentication_transaction(provider_id, redirect_uri)
  Core->>Core: create state/nonce/code_verifier transaction
  Core->>KC: build authorize URL (client_id, scope, state, nonce, pkce)
  Core-->>API: redirectUrl + state
  API-->>UI: 200 JSON {redirectUrl, state}
  UI->>KC: browser redirect to redirectUrl

  KC->>U: Show login screen
  U->>KC: Enter credentials + submit
  KC-->>API: GET /auth/callback?code=...&state=...
  API->>Core: complete_authentication_transaction(state, code)
  Core->>Core: validate state + load transaction
  Core->>KC: POST token endpoint (authorization_code + code_verifier)
  KC-->>Core: access_token + id_token (+ expires_in)
  Core->>KC: validate callback id_token (nonce/signature/claims)
  Core-->>API: token_response + original redirect_uri
  API-->>U: Set-Cookie X-Access-Token + X-ID-Token; redirect to redirect_uri

  UI->>API: GET /auth/get_user_profile
  API->>API: validate token (header or cookie), claim checks, user_type=staff
  API-->>UI: profile JSON
```

---

## Detailed flow (step by step)

## 1) UI loads login options

### UI action

User opens staff login page.

### API call

`GET /auth/get_login_providers`

### Backend behavior

1. Staff `AuthController` calls `auth_service.get_login_providers()`.
2. `AuthService` filters providers for `user_type="staff"` via `ProviderRepository`.
3. Response includes display fields (`id`, `name`, `displayName`, `displayIconUrl`).

### UI result

UI renders one or more buttons (for example: "Sign in with Keycloak Staff").

---

## 2) UI starts authentication transaction

### UI action

User clicks Keycloak login button.

### API call

`POST /auth/start_authentication_transaction?id=<provider_id>&redirect_uri=<ui_path_or_url>`

### Backend behavior

1. `AuthController.start_authentication_transaction(...)` calls:
   - `auth_service.start_authentication_transaction(provider_id, redirect_uri)`
2. `AuthService` validates provider exists.
3. The auth transaction store (in-memory or Redis per config) creates and stores:
   - `state` (CSRF protection)
   - `nonce` (ID token replay protection)
   - `code_verifier` (PKCE if enabled)
   - `redirect_uri` (original UI target after login)
4. Adapter (`keycloak` or default OIDC) builds authorize URL with:
   - `response_type=code`
   - `client_id`
   - `redirect_uri` (backend callback)
   - `scope` (`openid profile ...`)
   - `state`
   - `nonce`
   - PKCE `code_challenge` (if enabled)

### API response

```json
{
  "redirectUrl": "https://keycloak.example.com/realms/staff/protocol/openid-connect/auth?...",
  "state": "..."
}
```

### UI result

Frontend redirects browser to `redirectUrl`.

---

## 3) User authenticates at Keycloak

### Keycloak behavior

1. Keycloak shows login page.
2. User enters username/password (and MFA if configured).
3. On success, Keycloak redirects browser back to backend callback:

`GET /auth/callback?code=<authorization_code>&state=<state>`

---

## 4) Backend callback exchanges code for tokens

### API endpoint

`GET /auth/callback`

### Backend behavior

1. `AuthController.oauth_callback(...)` receives query params `code` and `state`.
2. It calls:
   - `auth_service.complete_authentication_transaction(state_value, code)`
3. `AuthService`:
   - loads and removes saved transaction from the transaction store (in-memory or Redis)
   - resolves provider + adapter
   - calls token endpoint with `authorization_code` grant
   - sends PKCE `code_verifier` if used
4. Keycloak returns `token_response`:
   - `access_token`
   - `id_token`
   - `expires_in` (optional)
   - other token fields
5. Adapter validates callback ID token (including nonce).
6. `AuthService` returns:
   - `token_response`
   - stored UI `redirect_uri`
7. Controller sets cookies:
   - `X-Access-Token`
   - `X-ID-Token`
8. Controller responds with redirect to original UI route.

### Cookie notes

Cookie options are controlled by staff API config:

- `auth_cookie_max_age`
- `auth_cookie_set_expires`
- `auth_cookie_path`
- `auth_cookie_httponly`
- `auth_cookie_secure`

---

## 5) UI fetches authenticated profile

### UI action

After callback redirect, UI calls:

`GET /auth/get_user_profile`

### Auth input

Token can come from:

- `Authorization: Bearer <access_token>` header, or
- `X-Access-Token` cookie

### Backend behavior

1. Auth dependency validates token:
   - issuer/audience policy
   - signature/JWKS (or introspection/hybrid, based on config)
2. `require_user_type("staff")` enforces staff-only access.
3. Returns normalized principal profile JSON.

### UI result

UI treats user as logged in and renders staff dashboard/permissions.

---

## 6) Logout flow

### API call

`POST /auth/logout`

### Backend behavior

- Deletes `X-Access-Token`
- Deletes `X-ID-Token`

### UI result

User session in this app ends (Keycloak SSO session may still exist unless RP-initiated logout is implemented).

---

## Endpoint summary

- `GET /auth/get_login_providers`
- `POST /auth/start_authentication_transaction`
- `GET /auth/get_login_provider_redirect/{id}` (direct redirect variant)
- `GET /auth/callback`
- `GET /auth/get_user_profile`
- `POST /auth/logout`

---

## Common failure points

- Invalid provider id -> start endpoint returns unauthorized error.
- Missing/expired transaction state -> callback fails.
- Wrong callback URL/client credentials -> token exchange fails.
- Nonce/state mismatch -> callback token validation fails.
- Issuer/audience mismatch -> protected APIs return unauthorized.
- `user_type` not mapped to `staff` -> profile/route returns forbidden.
