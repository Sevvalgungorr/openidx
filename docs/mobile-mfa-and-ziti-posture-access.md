# OpenIDX Mobile: MFA Authenticator + Posture-Gated Ziti Access

Audience: the OpenIDX mobile app developer.
Scope: the new built-in MFA authenticator and the tiered, posture-gated OpenZiti
access model. This doc is the contract; the backend pieces described here are
live on `https://openidx.tdv.org`.

---

## 1. Built-in MFA authenticator (offline TOTP)

The in-app authenticator (`mobile/src/features/authenticator/*`) is a standard
**offline RFC 6238 TOTP / RFC 4226 HOTP generator** — the same thing Google
Authenticator / Microsoft Authenticator do. It needs **no backend**: given a
secret and the current time it produces the rotating 6-digit code the relying
service verifies.

### Enrollment contract (what the app parses)

Accounts are added from an `otpauth://` URI (QR scan or manual entry):

```
otpauth://totp/<issuer>:<account>?secret=<BASE32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
otpauth://hotp/<issuer>:<account>?secret=<BASE32>&issuer=<issuer>&counter=0
```

- `secret` is base32 (RFC 4648, no padding required). Reject non-base32.
- `algorithm` ∈ {SHA1 (default), SHA256}. `digits` usually 6. `period` usually 30.
- `type` is `totp` (time-based) or `hotp` (counter-based).
- Store secrets in the OS keystore/keychain, never in plain app storage.

There is **no OpenIDX API call** for this feature — it interoperates with any
service that shows a TOTP QR (GitHub, Google, OpenIDX's own `/mfa/totp/*`, etc.).
If you want the app to also be OpenIDX's *push* MFA approver, that is a separate
server-backed flow under `/api/v1/identity/mfa/push/*` (register device →
receive challenge → verify) — not covered here.

---

## 2. The access model: enroll first, earn more later

Access over the OpenZiti overlay is **tiered**. Enrolling gets a device the
minimum; broader access (remote/PAM, admin surfaces) is **earned by passing
device posture**.

| Tier | Ziti identity attribute | What it can reach |
|------|-------------------------|-------------------|
| Tier 0 | none (public) | bootstrap only: login, JWKS, `/api/v1/access/enroll` |
| **Tier 1** | `enrolled-users` (granted at enroll) | user self-service, the console shell |
| **Tier 2** | `device-trusted` (granted when posture passes) | remote access (PAM SSH/RDP/VNC), admin-api, governance, audit, provisioning, SCIM |

Key rule: **enrolling does NOT grant Tier 2.** A freshly enrolled phone is
Tier 1 only. It becomes Tier 2 after it reports compliant device posture.

---

## 3. End-to-end sequence the app implements

```
(1) OAuth login            -> app has a user access token
(2) POST /agent/enroll/oauth   -> agent identity + Ziti enrollment JWT (Tier 1)
(3) native Ziti SDK enroll(jwt) -> identity online on the fabric  [see §4]
(4) POST /agent/report (posture) -> compliant => backend grants device-trusted (Tier 2)
(5) dial Tier-2 services (PAM remote access, etc.)  [see §6]
```

### (2) Enroll — get the Ziti JWT

```
POST /api/v1/access/agent/enroll/oauth
Authorization: Bearer <user access token>
-> { agent_id, device_id, auth_token, ziti_jwt, ... }
```

Also available (dark-platform / token path): `POST /api/v1/access/enroll` returns
`{ identity_name, ziti_enrollment_jwt }`.

**Controller address:** the JWT's `iss`/`ctrls` now carry the *public* controller
address `ctrl.tdv.org:1280` (reachable from the phone; DNS → <SERVER_IP>). This
was previously `ziti-controller.localtest.me:1280` which resolves to 127.0.0.1 on
a phone and caused `connection refused`. If you ever see a JWT with a
`localtest.me` (or otherwise unreachable) `ctrls`, treat it as stale and re-fetch
— the backend now auto-reissues a corrected token.

### (3) Native Ziti enroll — DO NOT fake success

```ts
await zitiEnroll(ziti_jwt);            // exchange OTT -> identity, store in Keystore/Keychain
const s = await zitiStatus();          // 'enrolled' | 'unenrolled' | 'error'
```

**Required fix (current app bug):** the UI shows "OpenZiti: enrolled ✓" even when
enrollment failed; relaunching flips it back to "not enrolled". Only render the ✓
after the SDK actually confirms an enrolled identity (`zitiStatus() === 'enrolled'`
and an edge-router connection is established). Catch `ConnectException` and show
an explicit **failed** state, do not swallow it.

### (4) Report posture — this is what unlocks Tier 2

Send the posture you already collect (`mobile/src/features/ziti/posture.ts`):

```
POST /api/v1/access/agent/report
X-Agent-ID: <agent_id>            (or agent_id in the body)
{
  "agent_id": "<agent_id>",
  "results": [
    { "check_type": "screen_lock",    "severity": "high",
      "result": { "status": "pass", "score": 100, "details": {}, "message": "..." },
      "ran_at": "2026-07-27T11:00:00Z" },
    { "check_type": "jailbreak_root", "severity": "critical",
      "result": { "status": "pass", "score": 100, "details": {}, "message": "..." },
      "ran_at": "2026-07-27T11:00:00Z" }
  ]
}
-> 202 { "status": "accepted", "compliance_score": <0..1>, "enforcement_actions": [...] }
```

Backend behavior:
- The server has platform-scoped posture checks (`screen_lock` high,
  `jailbreak_root` critical) tagged for `android`/`ios`. Report at least these
  `check_type`s. A `status:"fail"` on a **critical** check → non-compliant;
  on a **high** check → grace period.
- When the report is **compliant** (no critical/high failure), the backend adds
  the `device-trusted` attribute to your Ziti identity → **Tier 2 unlocked**.
  When it later fails, the attribute is removed → back to Tier 1.
- This gate is controlled server-side by `POSTURE_DEVICE_TRUST_GATE`
  (`off`|`observe`|`enforce`). During bring-up it may run in `observe` (logs the
  decision without changing access) before being flipped to `enforce`.

Report posture on launch, after significant device-state changes, and on a
periodic heartbeat so trust stays fresh (results expire after 24h).

---

## 4. Which check_types the backend understands

Send agent-evaluated software posture (the phone computes pass/fail):

| check_type | severity | pass condition |
|------------|----------|----------------|
| `screen_lock` | high | device lock / biometric enrolled |
| `jailbreak_root` | critical | not rooted / jailbroken |
| `play_integrity` | critical | (Android) Play Integrity token; server-verified |

`status` ∈ {`pass`,`fail`,`unknown`}. `unknown` is not counted as a failure.
Admins can add/scope more checks in the console (Ziti Network → Posture), tagging
them `android`/`ios` so they only apply to mobile.

---

## 5. Reaching remote access (PAM) over Ziti — Tier 2

Once `device-trusted`, the phone can dial brokered remote-access services
(SSH/RDP/VNC) published on the overlay. Flow:

1. List entitlements: `GET /api/v1/access/pam/entries` → each entry has a
   `reach_mode` (`direct` or `ziti`) and, when `ziti`, a `ziti_service_name`.
2. For a `ziti` entry, dial the service by name via the native SDK:
   ```ts
   const loopback = await zitiDial(ziti_service_name); // e.g. "127.0.0.1:<port>"
   ```
   Then point the SSH/RDP/VNC client (or the in-app viewer) at that loopback
   address — traffic rides the overlay to the target, no public exposure.
3. `POST /api/v1/access/pam/entries/:id/connect` brokers the session as today.

If a dial returns permission-denied, the identity is not Tier 2 yet — re-check
`zitiStatus()` and that the latest posture report was compliant.

---

## 6. What the backend now guarantees (this build)

- Mobile posture pipeline fixed: `posture_checks.platforms` exists (migration
  v111); android agents receive the mobile checks (previously errored, returning
  none).
- Posture → `device-trusted` tier gate wired (flagged rollout).
- Enrollment JWT carries the phone-reachable controller address.
- Baseline mobile posture checks seeded (`screen_lock`, `jailbreak_root`).

## 7. Mobile developer TODO (client side)

1. **Truthful enrollment state** — only show "enrolled ✓" after `zitiStatus()`
   confirms; surface `ConnectException` as a failure (§3).
2. **Report posture after enroll** and periodically (§3/§4) so Tier 2 is earned
   and stays fresh.
3. **Gate remote-access UI on trust** — only offer PAM dial when Tier 2; show a
   "complete device checks to unlock" state otherwise.
4. Test the `dial()` path against a `reach_mode:ziti` PAM entry (backend will
   provide one).

## 8. Admin action to finish enabling remote access over Ziti

One live admin step remains (requires an admin session, so it is done by an
OpenIDX admin, not baked into code):

- In the console: **Access → PAM entries → (pick an SSH/RDP entry) → Enable Ziti
  reach**, or call:
  ```
  POST /api/v1/access/pam/entries/<id>/ziti/enable
  Authorization: Bearer <admin token>
  ```
  This provisions the overlay service (`ziti_service_name`) + a loopback
  intercept port; the reconciler then publishes it and the PAM broker's
  ziti-tunnel binds it. After that, a Tier-2 phone can `zitiDial()` the service.

- To turn on the posture→tier gate, set on the access-service:
  `POSTURE_DEVICE_TRUST_GATE=observe` (watch first) then `=enforce`.

Until an entry is `reach_mode:ziti`, PAM sessions stay `direct` and the mobile
`dial()` path has nothing to target.

---

## 9. Concrete mobile TODO list (this iteration)

Grounded in the current app (`mobile/src/...`). Backend for all of these is live.

### 9.1 Fix the fake "✓ Enrolled" (CRITICAL) — `app/(app)/security/device.tsx`

Today:
```ts
const enrolled = !!identity.data;            // only the agent-enroll record
{enrolled ? '✓ Enrolled & managed' : 'Not enrolled'}
```
The screen already fetches `ziti = useQuery({ queryFn: zitiStatus })` but the
headline ignores it. Make enrollment truthful:
```ts
const agentEnrolled = !!identity.data;
const zitiOk = ziti.data === 'enrolled';       // from zitiStatus()
const enrolled = agentEnrolled && (!zitiAvailable() || zitiOk);
```
- Show three explicit states: **Enrolled** (both ok), **Overlay pending/failed**
  (agent ok, Ziti not `enrolled`), **Not enrolled**.
- In `enroll.mutationFn`, wrap `zitiEnroll(jwt)` in try/catch; on
  `ConnectException`/error set an error state and surface it — do NOT show the ✓.
- After a successful `zitiEnroll`, re-`invalidateQueries(['ziti-status'])` and
  confirm `zitiStatus() === 'enrolled'` before declaring success.

### 9.2 Actually route PAM remote access over Ziti (CRITICAL) — `features/pam/*`, `app/(app)/pam/session/[id].tsx`

`zitiDial()` exists in `features/ziti/native.ts` but is **never called**. For a
PAM entry with `reach_mode === 'ziti'`:
1. Before opening the session, call `const local = await zitiDial(entry.ziti_service_name)`.
2. Broker/open the session against that loopback address instead of the public
   Guacamole URL (the session screen currently just loads `url` in a WebView).
3. If `zitiStatus() !== 'enrolled'` or the identity isn't Tier-2 yet, block with a
   "complete device checks to unlock remote access" message.

Test target now live: PAM entry `test_main` (SSH), `ziti_service_name =
openidx-pam-7b54be1f-cb8b-4e83-894d-c66a73331efa`, intercept port 14000.

Note: the PAM list API already returns `reach_mode` and (extend the type to also
read) `ziti_service_name`. Add `ziti_service_name?: string` to the PAM entry type
in `features/pam/api.ts`.

### 9.3 Show the device tier / trust state — `security/device.tsx`

Reflect Tier-1 vs Tier-2 so the user knows what unlocks remote access. The
console reads this from `GET /api/v1/access/agents/{agent_id}/posture` →
`{ compliant, device_trusted, tier, results[] }`. The phone can call the same
endpoint (admin-gated) OR infer locally: "compliant posture reported → trusted".
Simplest: show a badge driven by whether the last `reportPosture` was compliant.

### 9.4 Report posture automatically + periodically — `security/device.tsx` / a background task

Currently posture is only sent on a manual button. Send it:
- right after a successful enroll,
- on app foreground,
- on a timer (results expire after 24h; every few hours is enough).
This keeps `device-trusted` fresh so Tier-2 doesn't lapse.

### 9.5 (Optional) "My Security" mobile screen

The console has `my-security` + `ai-identity-intelligence`; the app has no
equivalent. Add a screen backed by `GET /api/v1/identity/portal/security-insights`
(already live) showing the user's risk score, level, and tips — the same payload
the web `MySecurityPage` renders.

### Admin side (already shipped this iteration — for your awareness)

- **Agent Fleet → per-agent “View posture & tier”** shows each device's latest
  posture per check + its Tier-1/Tier-2 (`device-trusted`) state, so an admin can
  see exactly why a phone does/doesn't have remote access.
- **PAM Connections → “Enable Ziti reach”** button flips an entry to
  `reach_mode:ziti` from the UI.
- **Ziti Network → Posture checks** now supports platform scoping (android/ios).

---

## 10. App-open lock: biometric / passcode at launch (CRITICAL)

Requirement: when the app is opened (and when it returns to the foreground after
being away), require the device's Face ID / Touch ID / fingerprint, with the
device passcode as fallback, so it is certain the person holding the phone is the
account owner — before any account data, MFA codes, PAM targets, or approvals are
shown.

### What already exists

`app/(app)/_layout.tsx` already implements a `useAppLock()` gate: it locks on
launch and on every `background`/`inactive → active` transition and calls
`LocalAuthentication.authenticateAsync()`. Good foundation. But it has gaps that
every mature app (banking apps, 1Password, Google/Microsoft Authenticator) solve.

### How the reference apps actually do it (and what to copy)

- **Presence assertion, not authentication** (OWASP MASVS V4.5). The biometric
  prompt confirms "the enrolled device owner is here now"; it unlocks the already
  established OpenIDX session. It must NOT be treated as the login itself. Our
  session/token still comes from the OAuth/passkey flow — keep it that way.
- **Grace period.** Do NOT re-prompt on every brief app-switch. Banking apps and
  1Password use a configurable idle timeout (e.g. immediately / 1 min / 5 min).
  Record `lastBackgrounded = Date.now()` on background; on `active`, only lock if
  `now - lastBackgrounded > graceMs`. Current code locks on every `inactive`
  (even the pull-down notification shade), which is annoying enough that users
  disable it — the opposite of the goal.
- **Privacy screen while backgrounded.** In the app switcher / recents, mask the
  screen (a blur or a solid brand cover) so account data and TOTP codes aren't
  visible in the OS snapshot. iOS: cover on `willResignActive`; Android: set
  `FLAG_SECURE` on the window (also blocks screenshots).
- **Fallback chain.** `authenticateAsync({ promptMessage, disableDeviceFallback:
  false })` so a failed/absent biometric falls back to the device passcode. If
  the device has NO lock at all, decide policy: allow (current behavior) OR warn
  and require enrolling one for a security app. Recommend: allow but surface a
  "Your device has no lock — enable one" nudge (ties into the `screen_lock`
  posture check).
- **Bind secrets to the lock (L2 hardening).** Store the OpenIDX refresh/session
  token and the TOTP secrets in the keystore with a user-authentication-required
  key (iOS `.biometryCurrentSet` + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
  Android `setUserAuthenticationRequired(true)` +
  `setInvalidatedByBiometricEnrollment(true)`). Then a bypass of the JS boolean
  can't reach the secrets — the OS refuses to release them without a real
  biometric/passcode. `expo-secure-store` supports `requireAuthentication: true`;
  the authenticator secrets in `features/authenticator/store.ts` and the tokens
  in `features/ziti/device.ts` should use it.
- **User setting.** A Security setting: "Require Face ID / passcode to open" (on
  by default) + the grace-period picker (Immediately / After 1 minute / After 5
  minutes). Store the preference in secure storage. Most apps default this ON.
- **Re-lock on sensitive actions (step-up, MASVS V4.2).** Beyond app-open,
  re-prompt biometric right before high-impact actions: approving an MFA/login
  request, revealing a TOTP secret/QR, or starting a PAM remote session. This is
  the "certain it's really you" guarantee at the moment it matters, not just at
  open.

### Concrete tasks

1. `useAppLock()` — add a grace period (default 60s, from the user setting);
   only lock on `active` when `now - lastBackgrounded > graceMs`. Keep the
   immediate lock on true cold start.
2. Add `disableDeviceFallback: false` so passcode is the fallback; handle the
   "no hardware / not enrolled" branch explicitly (allow + nudge).
3. Privacy screen: iOS cover view on resign-active; Android `FLAG_SECURE`.
4. Migrate token + authenticator-secret storage to
   `SecureStore.setItemAsync(..., { requireAuthentication: true })` (or the
   platform keystore equivalents above) so secrets are OS-gated by the lock.
5. Add the Security setting (toggle + grace picker), default ON / 60s.
6. Step-up biometric before: approve request, reveal TOTP, start PAM session.
7. Localize the prompt copy (TR/EN): promptMessage "OpenIDX kilidini aç" /
   "Unlock OpenIDX".

### Acceptance

- Cold open → biometric/passcode required before any screen renders.
- Return after > grace period → prompt again; within grace → no prompt.
- App switcher shows a masked screen, not account data / TOTP codes.
- Biometric fail → device passcode fallback; success unlocks.
- Secrets unreadable without passing the OS auth (verify by disabling the lock).
- Setting toggles the whole behavior; default is ON.


