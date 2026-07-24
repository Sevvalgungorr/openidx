# OpenIDX Mobile — Test Findings and Development Backlog

**Test date:** 23 July 2026
**Device:** Xiaomi Redmi Note 13 (23106RN0DA), Android 15 (API 35), tested over ADB
**App:** `org.tdv.openidx` v1.0.0 (versionCode 1), installed 2026-07-23 14:07
**Backend:** `https://openidx.tdv.org` (192.168.31.76) — up, TLS valid (GlobalSign `*.tdv.org`, until 2027-04-14)

> Turkish version of this document: `OpenIDX-Mobil-Bulgu-Raporu.md` (same section numbering).

---

## Backend fix status (updated 24 July 2026)

Backend-side fixes landed and **verified live** against `openidx.tdv.org` (PR #558):

- **A1 (CRITICAL) — PAM inventory readable without auth: FIXED.** The box ran
  `APP_ENV=development`, where the data API used non-blocking `SoftAuth`. A new
  `ACCESS_API_REQUIRE_AUTH=true` flag now forces the same hard-blocking auth as
  production even in dev. Live: no-token `GET /api/v1/access/pam/entries` went
  **200 → 401**; a valid bearer still returns 200; the Tier-0 `POST /enroll` door
  stays reachable. This also removes the root cause behind A2/A3 "logged out"
  symptoms (identity now reaches the handlers instead of the fail-closed branch).
- **Z2 — enrollment JWT was 31 days stale: FIXED.** The mint path returned the
  stored OTT verbatim. It now checks expiry and, when stale, refreshes the
  controller's pending OTT (`POST /enrollments/{id}/refresh`, 7-day expiry) and
  persists a fresh JWT. Live: user `…-001` had an OTT expired `2026-06-22`; the
  enroll door now returns a JWT with `exp` ~7 days in the future.

Still **infra decisions** (need controller/DNS/broker changes, not just code):
- **Z1** — advertise the controller under a phone-resolvable FQDN (not
  `localtest.me`) + DNS record.
- **Z3** — the PAM ziti-broker/tunnel is not running on the box
  (`broker/status` → `ziti_broker:false`), so moving PAM entries to `reach_mode:
  ziti` needs the broker deployed first.
- **Full-dark** — bind data services loopback-only + trim the public edge so only
  enroll/oauth/well-known/console are reachable off-overlay.

Mobile-side items (WebView black screen, null-list crashes, notifications, FCM,
passkey management, Ziti SDK) are unchanged and remain with the app developer.

---

## 0. READ THIS FIRST: the app on the phone is not the project we handed over

We handed the developer the `D:\openidx\openidx-mobile` project (React Native + Expo SDK 57, TypeScript).
The APK installed on the phone is **not React Native — it is a native Kotlin / Jetpack Compose app.**

Evidence (APK unpacked and inspected):

| Expected (Expo/RN) | Found in the APK |
|---|---|
| `lib/arm64-v8a/libreactnative.so`, `libhermes.so` | Only `libandroidx.graphics.path.so` — no RN/Hermes |
| `assets/index.android.bundle` (JS bundle) | **Absent** |
| — | `kotlin-tooling-metadata.json`: Gradle 8.11.1, Kotlin 2.0.21, Android target |
| — | `androidx.compose.runtime.snapshots.*` in logcat (Jetpack Compose) |
| Screen title "Connections" (English) | Screen title **"Uzak erişim"** (Turkish) |

**Conclusion:** the developer rewrote the app from scratch as a native Android app. The good news: it
calls exactly the same set of API endpoints (extracted from the APK's DEX strings, below). The bad news:
the repo we hold is no longer the source of truth — **we need the developer to hand over the native
project's source code**, otherwise every future fix will be made blind.

Endpoints the APK actually calls (extracted from DEX):
```
/api/v1/governance/my-approvals, /requests, /requests/{id}
/api/v1/access/pam/entries, /entries/{id}, /my-entry-requests, /sessions/{id}
/api/v1/access/agent/enroll/oauth, /agent/report
/api/v1/identity/mfa/totp/{setup,enroll,status}
/api/v1/identity/mfa/push/{register,verify,devices,challenge/{id}}
/api/v1/identity/notifications, /mark-read, /mark-all-read
```
Present in the RN repo but **absent from the APK**: `/api/v1/identity/mfa/webauthn/*` (passkeys),
`/api/v1/access/enroll` (Ziti enrollment door), `/oauth/stepup-*` (step-up MFA).

---

## 1. OpenZiti: 0% — not implemented at all

The part you described as "I moved some services behind the Ziti network" **does not work on mobile at
all**, for the following reasons:

### 1.1 There is not a single line of Ziti code in the APK
Searching all three DEX files for `openziti`, `ziti-android` and `OidxZiti` returned **zero results**.
The native app also never calls `/api/v1/access/enroll` (the endpoint that issues the Ziti enrollment JWT).

### 1.2 The Ziti module in the RN repo is an empty scaffold too
`openidx-mobile/modules/ziti/` contains only three files: `README.md`, `expo-module.config.json`,
`index.ts`. The `ios/OidxZitiModule.swift` and `android/.../OidxZitiModule.kt` files that the README
tells you to "finish" **do not exist at all** — so HANDOFF.md's claim that "only the `dial()` loopback
proxy is left" is misleading; the entire native side still has to be written.

### 1.3 The JS side does not use Ziti either
`zitiDial()` and `zitiServiceAvailable()` are defined but **never called from anywhere**.
`src/app/(app)/pam/[id].tsx:88` only renders an "OpenZiti" badge when `reach_mode === 'ziti'`;
**the Connect button opens the same Guacamole WebView regardless of ziti vs. direct.**

### 1.4 Two concrete breakages on the backend Ziti side
`POST /api/v1/access/enroll` does return a real Ziti enrollment JWT (that part is ready), **but:**

**a) The controller address is unreachable from a phone.** JWT payload:
```json
{"iss":"https://ziti-controller.localtest.me:1280",
 "ctrls":["tls:ziti-controller.localtest.me:1280"], "em":"ott"}
```
`localtest.me` resolves to **127.0.0.1** in public DNS. Verified from the device:
```
$ adb shell ping ziti-controller.localtest.me
PING ziti-controller.localtest.me (127.0.0.1)
```
So the phone would try to connect to **itself** instead of the controller. Even if the native module
were written, enrollment could never complete in this state.

**b) The JWT expired 31 days ago.**
`exp = 1782122410` → **2026-06-22 10:00 UTC**. Test time: 2026-07-23.
The backend returns the same stale JWT on every request instead of minting a fresh one.

**c) The real controller hostname is not in DNS for the phone.** `ctrl.tdv.org` and `browzer.tdv.org`
are defined in the PC's hosts file only; from the phone they return `unknown host`.
(`openidx.tdv.org` is in corporate DNS and does resolve.)

**d) Neither existing PAM entry is actually behind Ziti:** both `test` and `test_main` report
`"ziti_enabled": false, "reach_mode": "direct"`.

### What needs to be done for Ziti
1. Advertise the Ziti controller under a real FQDN that resolves from a phone (e.g. `ctrl.tdv.org`)
   instead of `localtest.me`, and add that record to corporate DNS.
2. Make `/api/v1/access/enroll` mint a **fresh** JWT on every call (the current one appears cached).
3. Integrate the native Android Ziti SDK (`org.openziti:ziti-android`): `enroll`, `status`,
   `serviceAvailable`, `dial`.
4. Implement the 127.0.0.1 loopback proxy for `dial()`; when a PAM connection has `reach_mode == ziti`,
   point the WebView at that loopback address instead of directly at the server.
5. Actually move PAM entries onto Ziti (`ziti_enabled: true`) — otherwise there is nothing to test.

---

## 2. Broken endpoints — verified with a valid token

A real admin token was obtained via OAuth, then every endpoint each screen calls was tested individually.

### 2.1 "My access requests" screen — 401 (BROKEN)
```
GET /api/v1/access/pam/my-entry-requests
→ 401 {"error":"authentication required"}     (reproducible 3/3)

GET /api/v1/access/pam/entries                 (SAME TOKEN, same second)
→ 200 ✅
```
The same token works on every other endpoint but is rejected here. **Backend auth-middleware bug.**
This is why the "My PAM requests" row on the home screen does not open.

### 2.2 "This device" / device enrollment — 401 (BROKEN)
```
POST /api/v1/access/agent/enroll/oauth
→ 401 {"error":"user_id missing from auth context"}
```
The token **does** carry `sub: 00000000-0000-0000-0000-000000000001`, and
`POST /api/v1/access/enroll` reads that same user id from the same token and returns it as
`identity_name`. So the problem is not the token — it is how this endpoint derives its auth context.
**The "Enroll this device" button never works**, which in turn kills posture reporting and Ziti
enrollment downstream.

### 2.3 Step-up MFA — impossible on mobile
```
POST /oauth/stepup-challenge
→ 401 {"error":"unauthorized",
       "error_description":"valid session required for step-up authentication"}
```
The endpoint requires a **cookie session**. A mobile app has no cookies, only a Bearer token. This
endpoint must be fixed to accept Bearer for mobile. (Note: in the RN repo, `stepup.ts` is never called
from any screen — dead code; it is absent from the native APK as well.)

### 2.4 Endpoints that work ✅
| Screen | Endpoint | Result |
|---|---|---|
| Approvals | `GET /api/v1/governance/my-approvals` | 200, returns data |
| My Access | `GET /api/v1/governance/requests?requester_id=me` | 200 (empty list) |
| Notifications | `GET /api/v1/identity/notifications` | 200, 2 unread |
| Notification badge | `GET .../notifications/unread-count` | 200 |
| Authenticator | `GET /api/v1/identity/mfa/totp/status` | 200 |
| Remote access | `GET /api/v1/access/pam/entries` | 200 |
| Connect | `POST /api/v1/access/pam/entries/{id}/connect` | 200, returns Guacamole URL |

**Note:** `webauthn/credentials` and `push/devices` return JSON `null` instead of an empty list.
If the native app is not null-safe this will crash it; the backend should return `[]`.

---

## 2.5 ON-DEVICE WALKTHROUGH (every screen driven over ADB)

Every screen of the app was opened one by one on the phone. Results:

| # | Screen | Result |
|---|---|---|
| 1 | Home | ✅ Opens — **but there are no badges at all** (pending-approval and unread-notification counts are not shown) |
| 2 | My Access | ✅ Works (Roles: admin, Groups: Administrators, "No access requests") |
| 3 | Approvals | ✅ List loads (1 pending: manager / David Kim) |
| 4 | Approval detail | ✅ Fully works — Resource/Type/Requester/Priority/Justification + **Approve / Deny** buttons |
| 5 | Notifications | ⚠️ List loads, but **tapping a notification does nothing** — cannot be marked read |
| 6 | Remote access (list) | ✅ Both connections listed |
| 7 | **Session (PAM connection)** | ❌ **BLACK SCREEN** — details below |
| 8 | **My access requests** | ❌ **THE APP LOGS THE USER OUT** |
| 9 | Security & MFA | ✅ Menu opens — **no passkey management in the menu** |
| 10 | Authenticator (TOTP) | ✅ Fully works — QR code + secret key + code entry field |
| 11 | **Push approvals** | ❌ **CRASHES** — details below |
| 12 | This device | ✅ Opens, posture checks work — **no OpenZiti row** |
| 13 | **Enroll this device** | ❌ **THE APP LOGS THE USER OUT** |
| 14 | Sign-in (OAuth) | ✅ Works — Custom Tab, **v1** flow |

### 🔴 Finding A — Two screens throw the user out of the app

Tapping **"My access requests"** or **"Enroll this device"** immediately drops the user to the login
screen and wipes the session.

Cause: the endpoints these two screens call return 401 (§2.1 and §2.2). The app's HTTP layer treats any
401 as "session invalid", clears the tokens and routes to login.

So these two backend 401s do not merely break a screen — **they destroy the user's entire session.**
This is the most damaging consequence from a UX standpoint.

> Additional recommendation (mobile): do not log out blindly on 401. Attempt a token refresh first and
> only log out if the refresh also fails. A single endpoint's 401 must not tear down the whole session.

### 🔴 Finding B — PAM session shows a black screen (app WebView issue)

Opening a connection from the "Remote access" list brings up the "Session" screen, but the display is
**completely black**. Waited 15+ seconds, no change. Identical for both the SSH (`test_main`) and RDP
(`test`) entries.

Diagnostics performed:
- The Guacamole client **does load** — Guacamole's own menu items ("Upload Files", "Back") appear in the
  WebView's accessibility tree.
- The tunnel **does connect** — logcat shows an AAudio/AudioTrack stream opening (Guacamole's audio channel).
- **No network errors** — not a single `net::ERR_` in the chromium logs.
- Target hosts are **reachable** (192.168.31.85:3389 ✅, 192.168.31.76:22 ✅).
- The backend `connect` endpoint **produces correct URLs** (distinct connection ids: `#/client/1` and `#/client/2`).

**Decisive discriminator:** the **exact same `connect_url`** produced by the app was opened in Chrome
**on the same phone, on the same network** → **the RDP desktop rendered perfectly.**

➡️ Backend, Guacamole, networking and credentials are all sound. The problem is in **the app's own
WebView configuration**. Things for the developer to check: hardware acceleration / `setLayerType`,
`WebSettings` (JavaScript, DOM storage, `mediaPlaybackRequiresUserGesture=false`), and the WebView's
measured size (Guacamole derives its display dimensions from the WebView — a zero size yields a black screen).

### 🔴 Finding C — "Push approvals" screen crashes with a JSON error

This is shown to the user verbatim on screen:
```
Bir şeyler ters gitti            (Something went wrong)
Unexpected JSON token at offset 0: Expected start of the array '[',
but had 'n' instead at path: $
JSON input: null
```
Cause: `GET /api/v1/identity/mfa/push/devices` returns JSON **`null`** instead of an empty list
(also observed in the API testing in §2.4). Kotlin's `kotlinx.serialization` cannot deserialize `null`
into `List<PushDevice>` and throws.

Should be fixed on both sides:
- **Backend:** return `[]` instead of `null` (the same problem exists on `webauthn/credentials`).
- **Mobile:** deserialize list fields null-safely (`?: emptyList()`).

### ⚠️ Finding D — Notifications can never be marked read

Tapping a notification does nothing; `unread-count` stays fixed at **2**. The endpoints
`/notifications/mark-read` and `/mark-all-read` **are present** in the APK but are not wired to any UI
element. On top of that the home screen shows no unread badge at all → the user can never clear
notifications.

### ⚠️ Finding E — Passkeys: offered at login, unmanageable in the app

The login screen offers a **"Sign in with passkey"** button, but the "Security & MFA" menu contains
**no** passkey enrollment/management screen and the APK never calls any `webauthn` endpoint. So there is
nowhere for a user to create a passkey — even if the button worked, no passkey could ever be registered.
(Compounded by the `assetlinks.json` 404 issue in §4.2.)

---

## 3. OAuth sign-in flow

**The native app on the device uses the v1 flow and sign-in works end to end ✅**
(Custom Tab opens → username/password → returns to the app via `openidx://oauth-callback`).
The v2 problem described below therefore does not affect users today, but the endpoint is broken on the server.

The page the user actually sees at sign-in reads **"Welcome to Acme Corp" / "Sign in to your Acme
workspace" / "© 2026 Acme Corp — test branding"** — in the live environment, to real users.
This needs fixing urgently.

The RN repo uses this endpoint at `src/lib/auth.tsx:44`: `${OAUTH_BASE_URL}/authorize/v2`.

```
GET /oauth/authorize/v2?client_id=openidx-mobile&...
→ 302 Location: /oauth/login?login_session=<token>&redirect_uri=openidx://oauth-callback

GET /oauth/login?login_session=<same token>
→ 400 {"error":"invalid_request",
       "error_description":"login session expired; restart sign-in"}
```
**Failed 8/8 attempts.** Browser User-Agent, `Accept: text/html`, following the redirect on a single
connection — all tried, none made a difference. `/oauth/login` rejects the login session that
`authorize/v2` just issued, **immediately**.

By contrast, **the v1 flow works flawlessly** (verified end to end):
```
GET  /oauth/authorize            → 200, login form
POST /oauth/authorize/callback   → 302 openidx://oauth-callback?code=...
POST /oauth/token                → access_token + refresh_token + id_token ✅
```

Two additional inconsistencies:
- OIDC discovery (`/.well-known/openid-configuration`) advertises **v1** (`/oauth/authorize`) as the
  `authorization_endpoint`, while the app uses **v2**.
- The v1 login page still reads **"Welcome to Acme Corp — Acme Identity / © 2026 Acme Corp — test
  branding"**. Corporate branding must be applied.

---

## 4. Security findings

### 4.1 🔴 CRITICAL — The PAM inventory is readable without authentication
```
GET https://openidx.tdv.org/api/v1/access/pam/entries      (NO Authorization header)
→ 200 OK
{"entries":[{"name":"test","entry_type":"rdp","hostname":"192.168.31.85","port":3389,
  "username":"aykut.ayvaz","domain":"test","has_secret":true, ...},
 {"name":"test_main","entry_type":"ssh","hostname":"192.168.31.76","port":22,
  "username":"cmit", ...}]}
```
Hostnames, ports, **usernames**, domain information and which entries have a stored password
(`has_secret`) are fully exposed. This endpoint must be put behind authentication immediately.

### 4.2 🟠 Passkeys cannot possibly work — domain association files missing
```
GET /.well-known/assetlinks.json                → 404
GET /.well-known/apple-app-site-association     → 404
```
The APK bundles `androidx.credentials` + `play-services-fido` (Credential Manager / WebAuthn), so the
passkey plumbing is in the app. But without `assetlinks.json`, Android **refuses** to bind a passkey to
the `openidx.tdv.org` RP ID. Since the backend expects `WEBAUTHN_RP_ORIGINS=https://openidx.tdv.org`,
this file must be published (with the app package name `org.tdv.openidx` + signing-certificate SHA-256).

### 4.3 🟡 Guacamole session token in the URL
The `connect` response: `https://openidx.tdv.org/guacamole/#/client/1?token=28E25B2B...`
The token sits in the URL fragment; it is not sent to the server, but it can persist in WebView history
and logs.

---

## 5. Push / notifications — no infrastructure at all

| Check | Result |
|---|---|
| APK permissions | Only `INTERNET` and `USE_BIOMETRIC` |
| `POST_NOTIFICATIONS` permission | **Absent** → on Android 13+ the app cannot display notifications at all |
| Firebase / FCM (`firebase-messaging`, `FirebaseMessagingService`) | **Completely absent** from the APK |
| `google-services.json` | Absent |

Conclusion: **push-MFA notification delivery is impossible.** Only the polling / deep-link
(`openidx://approve/<id>`) path exists today. The deep-link scheme (`openidx://`) is correctly
registered in the manifest ✅.

(In the RN repo, `expo-notifications` is listed as a dependency but is never imported by any file — a dead dependency.)

---

## 6. Prioritised backlog for the developer

### URGENT (users are hitting these right now)
| # | Task | Impact | Side |
|---|---|---|---|
| A1 | `GET /api/v1/access/pam/entries` — require authentication | 🔴 Hostnames/usernames/ports publicly exposed | Backend |
| A2 | `GET /api/v1/access/pam/my-entry-requests` 401 bug | **User is thrown out of the app** | Backend |
| A3 | `POST /api/v1/access/agent/enroll/oauth` → "user_id missing from auth context" | **User is thrown out of the app** + device enrollment/posture/Ziti chain is dead | Backend |
| A4 | PAM session black screen — WebView configuration | **Remote access is entirely unusable** | Mobile |
| A5 | `push/devices` and `webauthn/credentials` must return `[]` instead of `null` | "Push approvals" screen crashes | Backend |
| A6 | Deserialize list fields null-safely (`?: emptyList()`) | Defence against the same class of crash | Mobile |
| A7 | Do not log out blindly on 401 — try refresh first | One endpoint's failure must not kill the session | Mobile |
| A8 | Remove the **"Acme Corp"** test branding from the login page | Real users see it in production | Backend |

### OpenZiti (the requested feature — currently at 0%)
| # | Task | Side |
|---|---|---|
| Z1 | Advertise the Ziti controller under a real FQDN resolvable from a phone (not `localtest.me`) + add DNS record | Backend/Infra |
| Z2 | `/api/v1/access/enroll` must mint a fresh JWT per call (current one is 31 days stale) | Backend |
| Z3 | Actually move PAM entries onto Ziti (`ziti_enabled: true`) — both are `direct` today | Backend |
| Z4 | Integrate the OpenZiti Android SDK (`enroll` / `status` / `serviceAvailable` / `dial`) | Mobile |
| Z5 | 127.0.0.1 loopback proxy for `dial()`; route `reach_mode == ziti` connections through it | Mobile |

### Missing / half-finished features
| # | Task | Side |
|---|---|---|
| E1 | **Hand over the native project's source code** — the RN repo we hold is no longer valid | Mobile |
| E2 | Mark-as-read UI for notifications (endpoints ready, no UI) + home-screen badges | Mobile |
| E3 | Passkey management screen (add/remove) — the login button exists but there is nowhere to enrol | Mobile |
| E4 | Publish `.well-known/assetlinks.json` (package `org.tdv.openidx` + signing SHA-256) | Backend |
| E5 | `POST_NOTIFICATIONS` permission + FCM integration (`google-services.json`) → push-MFA delivery | Mobile |
| E6 | `/oauth/stepup-challenge` should accept a Bearer token | Backend |
| E7 | `/oauth/authorize/v2` → `/oauth/login` "session expired" | Backend |
| E8 | OIDC discovery advertises v1 as `authorization_endpoint` — align it | Backend |
| E9 | Add crash/error reporting to the release build — logcat contains no application logs at all, making diagnosis impossible | Mobile |

---

## Appendix: test environment notes

- During testing the phone was on the corporate WiFi (`CMIT_YONETIM`, 192.168.1.74) with VPN active.
  `openidx.tdv.org` resolves in that environment (192.168.31.76) ✅. **It does not resolve over mobile
  data** — if the app is expected to work outside the corporate network, this must be addressed
  separately (this is precisely the problem Ziti/BrowZer is meant to solve).
- MIUI blocks ADB input injection by default (no `INJECT_EVENTS` permission). To drive the app
  automatically, Developer Options → **"USB debugging (Security settings)"** must be enabled. It was
  enabled for this test run; consider turning it off again afterwards, since it lets a connected
  computer simulate taps and typing on the device.
