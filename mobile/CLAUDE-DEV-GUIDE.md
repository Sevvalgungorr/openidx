# OpenIDX Mobile — Claude Development Guide

A single, self-contained brief for building the OpenIDX Authenticator + companion
app **with Claude (or any coding agent)**. It covers: how to run, the exact
backend endpoints the app uses, the app's internal logic/architecture, and a
prioritized feature roadmap (what to **add**, what to **exclude**) benchmarked
against Microsoft/Google/Duo/Okta authenticators.

> Read order for an agent: this file → `CLAUDE.md` → `HANDOFF.md` →
> `docs/mobile-developer-guide-simple.md`. Then open an existing screen in
> `src/app/(app)/` and copy its structure.

---

## 1. What this app is

React Native + **Expo SDK 57** (TypeScript, `expo-router`) companion + MFA
authenticator for the OpenIDX identity platform. It talks to **one HTTPS host**
(`https://openidx.tdv.org` by default) and is already feature-complete for:

- OAuth **PKCE** login + native **passkey** login + silent token refresh
- MFA: **TOTP** (offline code generator + QR scan), **push approve**
  (number-matching), **passkey** enroll, **step-up**
- **Push authenticator QR self-enrollment** (scan the console QR to bind this
  phone as a push device — Google/MS-Authenticator style)
- **Approvals** inbox (approve/deny access requests)
- **My Access** (your access requests)
- **Notifications** (list, unread, mark-read, push-config)
- **PAM**: browse entries, request access, launch a session (Guacamole WebView)
- **Device enrollment + posture**, and an **OpenZiti** native-module scaffold
  (not yet compiled)

### Golden rules (do not violate)
1. **Expo SDK 57.** Read `https://docs.expo.dev/versions/v57.0.0/` before using
   any Expo API. Do not guess API shapes across SDKs.
2. **One backend host.** Everything is under `API_BASE_URL`. Never hard-code a
   service port or per-service URL. (`src/config.ts`.)
3. **Use the shared client** `import { api } from '@/lib/api'` — it injects the
   Bearer token + `X-Org-Slug` and refreshes once on 401.
4. **Match existing patterns**: `@tanstack/react-query` (`useQuery`/`useMutation`)
   + `expo-router` `Stack.Screen`. Copy a neighboring screen; don't invent a new
   structure.
5. **Type-check before "done":** `npx tsc --noEmit`.
6. **Never store long-lived secrets in JS state or AsyncStorage.** Tokens live in
   `expo-secure-store` (see `src/lib/secureStore.ts`).

---

## 2. Run it

```bash
npm install
npx expo start          # press i (iOS sim) / a (Android) / scan QR in Expo Go
# or: npm run ios | npm run android
npx tsc --noEmit        # typecheck
```

- Backend: `https://openidx.tdv.org` (reference box). Test login `admin` /
  `Admin@123`. To reach the host from a device you may need VPN or an
  `/etc/hosts` entry for `*.tdv.org` (ask the operator).
- Change backend without editing code: `app.json → expo.extra.apiBaseUrl`.
- Native modules (`expo-camera`, `react-native-passkeys`, OpenZiti) need a
  **dev-client / EAS build**, not plain Expo Go. Screens degrade gracefully in
  Expo Go (camera scan shows a hint; passkeys fall back).

---

## 3. Backend endpoint reference (what the app calls)

Base = `API_BASE_URL` (`https://openidx.tdv.org`). All are prefixed as shown.
Auth = `Authorization: Bearer <access_token>` added automatically by `api`,
except where noted "public".

### Auth / OAuth  (`src/lib/oauth.ts`, `src/lib/auth.tsx`, `src/features/mfa/*`)
| Method | Path | Purpose |
|---|---|---|
| GET  | `/oauth/authorize` | Start PKCE (opens in `expo-web-browser`) |
| POST | `/oauth/token` | Exchange code / refresh (`grant_type=authorization_code|refresh_token`) |
| POST | `/oauth/native/login-init` | Begin native passkey login (mints a login_session) |
| POST | `/oauth/passkey-begin` / `/oauth/passkey-finish` | Passkey (WebAuthn) assertion for login |
| POST | `/oauth/stepup-challenge` / `/oauth/stepup-verify` | Step-up re-auth for sensitive actions |

### MFA — TOTP  (`src/features/mfa/totp.ts`)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/identity/mfa/totp/setup` | Get secret + `otpauth://` provisioning URI |
| POST | `/api/v1/identity/mfa/totp/enroll` | Activate with a code |
| GET  | `/api/v1/identity/mfa/totp/status` | Enrollment status |
| DELETE | `/api/v1/identity/mfa/totp` | Disable |

### MFA — Push authenticator  (`src/features/mfa/push.ts`)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/identity/mfa/push/register` | Register this device (bearer) |
| GET  | `/api/v1/identity/mfa/push/devices` | List this user's push devices |
| DELETE | `/api/v1/identity/mfa/push/devices/{id}` | Remove a device |
| GET  | `/api/v1/identity/mfa/push/challenge/{id}` | Poll a challenge (number redacted) |
| POST | `/api/v1/identity/mfa/push/verify` | Approve/deny with the matched number |
| POST | `/api/v1/identity/mfa/push/enroll/start` | (console) mint a QR enroll ticket |
| POST | `/api/v1/identity/mfa/push/enroll/complete` | **public** — bind device via scanned ticket |

### MFA — Passkey  (`src/features/mfa/passkey.ts`)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/identity/mfa/webauthn/register/begin` | Begin passkey enroll |
| POST | `/api/v1/identity/mfa/webauthn/register/finish` | Finish passkey enroll |
| GET  | `/api/v1/identity/mfa/webauthn/credentials` | List passkeys (bare array) |

### Approvals & My Access  (`src/features/approvals/api.ts`, `src/features/myaccess/api.ts`)
| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/v1/governance/my-approvals` | Pending approvals assigned to me |
| POST | `/api/v1/governance/requests/{id}/approve` | Approve |
| POST | `/api/v1/governance/requests/{id}/deny` | Deny |
| GET  | `/api/v1/governance/requests?requester_id=me&limit=50` | My requests |

### Notifications  (`src/features/notifications/api.ts`)
| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/v1/identity/notifications?limit=50[&unread=true]` | List |
| GET  | `/api/v1/identity/notifications/unread-count` | Badge count (`{unread_count}`) |
| POST | `/api/v1/identity/notifications/mark-read` | Mark specific read (`{notification_ids}`) |
| POST | `/api/v1/identity/notifications/mark-all-read` | Mark all read |
| GET/POST | `/api/v1/identity/notifications/push-config` | Push delivery config |

### PAM  (`src/features/pam/api.ts`)
| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/v1/access/pam/entries[?q=]` | Browse entries |
| POST | `/api/v1/access/pam/entries/{id}/request` | Request access |
| GET  | `/api/v1/access/pam/my-entry-requests` | My PAM requests |
| POST | `/api/v1/access/pam/entries/{id}/connect` | Launch a session |
| POST | `/api/v1/access/pam/sessions/{sessionId}/end` | End session |

> **Contract notes (learned the hard way):** several list endpoints return a
> **bare array** or a `{key: [...]}` wrapper — check the exact shape in the
> feature file, don't assume. Unread-count is `{unread_count}` not `{count}`.
> The backend has a `contractcheck` tool that flags console mismatches; the
> mobile app should mirror the same shapes.

---

## 4. App architecture / logic map

```
src/
  config.ts            API_BASE_URL, OAuth client/scopes/redirect
  lib/
    api.ts             axios client: injects Bearer + X-Org-Slug, refresh-on-401
    auth.tsx           AuthProvider/useAuth: session state + onAuthLost -> login
    oauth.ts           PKCE authorize/exchange/refresh
    pkce.ts            code_verifier/challenge
    jwt.ts             decode/inspect access token
    secureStore.ts     expo-secure-store wrappers (tokens, org slug, install id)
  features/<f>/api.ts  typed API calls per feature (the ONLY place URLs live)
  features/authenticator/
    otp.ts             TOTP code generation + parseOtpauthUri
    store.ts           local encrypted account store (the offline authenticator)
    crypto.ts          HMAC/base32 for TOTP
  app/(auth)/login.tsx           login screen (PKCE + passkey)
  app/(app)/index.tsx            home
  app/(app)/authenticator/       TOTP accounts: list / add / scan (QR)
  app/(app)/approve/[challengeId].tsx   push number-match approve
  app/(app)/approvals/           access-request approvals inbox
  app/(app)/security/            totp / passkeys / device (posture)
  app/(app)/pam/                 browse / request / session
  app/(app)/notifications.tsx
  modules/ziti/                  native OpenZiti scaffold (not compiled)
```

**Data flow of one screen** (copy this shape):
1. `useQuery(['key'], () => featureApi.list())` for reads; `useMutation` for
   writes, then `queryClient.invalidateQueries`.
2. All HTTP via `api` (never bare `fetch`, except the **public** push
   enroll/complete which deliberately carries no bearer).
3. Errors surface via a toast/Alert; never swallow silently.

**Auth lifecycle:** `auth.tsx` holds tokens in secure store; `api.ts` refreshes
once on 401 and calls `onAuthLost()` to route to `/(auth)/login` on a hard 401.

---

## 5. Feature roadmap — what to ADD vs EXCLUDE

Benchmarked against Microsoft Authenticator, Google Authenticator, Duo Mobile,
Okta Verify, Authy. OpenIDX is an **enterprise IAM companion**, so the bar is
"Okta Verify / Duo Mobile", not consumer 2FA.

### Already have (don't rebuild)
TOTP (offline + QR scan), push number-match approve, passkey login + enroll,
push QR self-enrollment, approvals inbox, PAM launch, device posture, biometric
app-lock, OAuth PKCE + refresh.

### ADD — high value, in priority order
| # | Feature | Why (competitor parity) | Rough size |
|---|---|---|---|
| 1 | **Real FCM/APNs push delivery** for approvals | Duo/Okta/MS all deliver a real push; today challenges are poll/deep-link. Backend already speaks FCM HTTP v1 + APNs (`internal/identity/pushmfa_providers.go`) — needs Firebase/APNs creds + `expo-notifications` token registration. | M |
| 2 | **Encrypted account backup + restore / multi-device** | Authy's headline feature; Google/Okta added export. Protects TOTP seeds on device loss. Encrypt with a user passphrase; store blob server-side or export file. | M–L |
| 3 | **Passwordless "phone sign-in"** (approve login from the app) | MS/Okta core: sign in with no password, approve on phone. Reuse push + number-match. | M |
| 4 | **Rich approval context** (who/what/where/when, map, risk score) | Okta/Duo show device, location, IP, app on the approve screen to fight MFA fatigue. Backend has risk + geo. | S–M |
| 5 | **Number-matching + geo-deny on approvals** (anti-fatigue) | MS made number-matching mandatory in 2023. We have number-match; add "deny + report suspicious". | S |
| 6 | **TOTP account icons/search/reorder/folders** | Quality-of-life once users hold many accounts (Authy/MS). | S |
| 7 | **Widget / quick-glance codes** (iOS/Android widget) | Google/Authy added widgets; big UX win. | M |
| 8 | **Verified push + FIDO2 device-bound keys** for high-assurance | Okta FastPass / MS "device-bound passkey". We have passkeys; bind approvals to a device key. | L |
| 9 | **Offline approval (QR challenge / verification code)** | Duo/Okta offline mode when the phone has no network. | M |
| 10 | **In-app secure messaging / step-up for admin actions** | Enterprise console parity (approve privileged ops from phone). | M |

### EXCLUDE — deliberately out of scope
- **Password manager / autofill** (MS Authenticator does this) — OpenIDX is IAM,
  not a consumer vault; keep the app focused on identity/MFA/PAM.
- **Consumer social-account 2FA marketing** — this is an enterprise companion.
- **SMS/voice OTP as a primary factor** — phishable; the platform supports it
  server-side but the app should push passkey/push, not build SMS UX.
- **Cross-platform desktop app** (Authy-style) — out of scope for the mobile repo.
- **Custom crypto** — never hand-roll TOTP/crypto beyond the vetted
  `authenticator/crypto.ts`; use platform primitives (`expo-crypto`).
- **Storing tokens/seeds outside `expo-secure-store`** — non-negotiable.

### Non-functional must-haves before shipping to a store
- App-lock (biometric) on launch and before revealing codes — present, verify.
- Jailbreak/root signal in posture (device.ts) — extend.
- Certificate handling for the backend host; no cleartext.
- Domain-association files for passkeys (`apple-app-site-association`,
  `assetlinks.json`) hosted at `openidx.tdv.org` (see `HANDOFF.md §4`).

---

## 6. How to develop this with Claude (recipe)

1. **Give Claude this file + the target feature's `src/features/<f>/api.ts` and
   its screen.** Ask it to state the endpoint contract first.
2. **One feature per change.** e.g. "Add real FCM push registration": register
   an `expo-notifications` token on login, POST it to
   `/mfa/push/register` as `device_token`, and handle the notification tap →
   `/(app)/approve/[challengeId]`.
3. **Always:** copy an existing screen's structure, use `api` + react-query,
   then `npx tsc --noEmit`, then run on a device/simulator.
4. **Verify against the live backend** (`admin`/`Admin@123`) — the endpoints in
   §3 are real and respond today.
5. **Don't touch native modules** (`modules/ziti/`) unless the task is
   explicitly the Ziti proxy; it needs a native build toolchain.

---

## 7. Backend cross-references (source of truth)
- Push MFA + QR enroll: `internal/identity/pushmfa.go`, `pushmfa_enroll.go`,
  `pushmfa_providers.go`
- TOTP: `internal/identity/service.go` (`/mfa/totp/*`)
- Passkey/WebAuthn: `internal/identity/webauthn.go`
- OAuth/PKCE + login_session: `internal/oauth/authorize.go`, `service.go`
- Governance approvals: `internal/governance/`
- PAM: `internal/access/pam_*.go`
- Full API contract with request/response examples:
  `docs/mobile-authenticator-developer-guide.md`
