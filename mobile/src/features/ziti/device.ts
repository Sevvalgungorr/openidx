/**
 * Phase 3 — the phone as a managed, posture-reporting OpenIDX device.
 *
 * Because the app is already OAuth-authenticated, it enrolls straight through
 * the existing OAuth agent path (no separate token): POST /agent/enroll/oauth
 * creates the agent, auto-provisions a Ziti identity (returns `ziti_jwt` for the
 * native Ziti module to enroll), and files a device-trust entry. Posture is
 * reported via POST /agent/report. Agent creds live in the keystore.
 */
import * as Crypto from 'expo-crypto';
import * as Device from 'expo-device';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

import { api } from '@/lib/api';
import type { PostureResult } from '@/features/ziti/posture';

const BASE = '/api/v1/access';
const AGENT_ID = 'oidx.agent_id';
const DEVICE_ID = 'oidx.agent_device_id';
const AUTH_TOKEN = 'oidx.agent_auth_token';
const ZITI_JWT = 'oidx.ziti_jwt';
const DEVICE_FINGERPRINT = 'oidx.device_fingerprint';

export type EnrollResult = {
  agent_id: string;
  device_id: string;
  auth_token: string;
  status: string;
  ziti_jwt?: string;
};

export type AgentIdentity = { agentId: string; deviceId: string } | null;

export async function getAgentIdentity(): Promise<AgentIdentity> {
  const agentId = await SecureStore.getItemAsync(AGENT_ID);
  const deviceId = await SecureStore.getItemAsync(DEVICE_ID);
  return agentId && deviceId ? { agentId, deviceId } : null;
}

/**
 * A stable per-install device fingerprint. The backend keys enrollment dedup on
 * `device_fingerprint`: without a stable value every re-enroll mints a NEW
 * agent row, so one physical phone shows up as many duplicate agents. We mint a
 * random UUID once and persist it in the secure keystore, so it survives app
 * restarts and re-enrolls (a factory reset / reinstall that clears the keystore
 * intentionally yields a fresh device identity). Namespaced `mobile:` so it
 * never collides with the desktop agent's machine-GUID fingerprints.
 */
async function getDeviceFingerprint(): Promise<string> {
  const existing = await SecureStore.getItemAsync(DEVICE_FINGERPRINT);
  if (existing) return existing;
  const fp = `mobile:${Crypto.randomUUID()}`;
  await SecureStore.setItemAsync(DEVICE_FINGERPRINT, fp);
  return fp;
}

/** Enroll this device (OAuth path — uses the signed-in session). Idempotent:
 *  the backend reconciles by the stable device_fingerprint we send, so
 *  re-enrolling the same phone reuses its agent_id instead of duplicating it. */
export async function enrollDevice(): Promise<EnrollResult> {
  const res = await api.post<EnrollResult>(`${BASE}/agent/enroll/oauth`, {
    hostname: Device.deviceName ?? `${Platform.OS}-device`,
    os: Platform.OS,
    arch: Device.modelName ?? 'unknown',
    // Send the concrete OS ('android' | 'ios') so the backend records the real
    // platform; 'mobile' would normalize to 'unknown' and break posture checks.
    platform: Platform.OS,
    form_factor: Device.deviceType === Device.DeviceType.TABLET ? 'tablet' : 'phone',
    management_mode: 'byod',
    device_fingerprint: await getDeviceFingerprint(),
  });
  await SecureStore.setItemAsync(AGENT_ID, res.agent_id);
  await SecureStore.setItemAsync(DEVICE_ID, res.device_id);
  if (res.auth_token) await SecureStore.setItemAsync(AUTH_TOKEN, res.auth_token);
  if (res.ziti_jwt) await SecureStore.setItemAsync(ZITI_JWT, res.ziti_jwt);
  return res;
}

/** The Ziti enrollment JWT (for the native Ziti module to enroll an identity). */
export function getZitiJwt(): Promise<string | null> {
  return SecureStore.getItemAsync(ZITI_JWT);
}

/**
 * Dark-platform enroll door (Tier-0): POST /api/v1/access/enroll.
 *
 * The ONLY access-service route that stays public when the platform goes dark.
 * It trades the signed-in session (Authorization: Bearer, injected by the api
 * client) for a one-time OpenZiti enrollment JWT, which the native Ziti module
 * uses to join the overlay and reach every (now-dark) service.
 *
 * Prefer this over the JWT embedded in enrollDevice()'s response when the
 * platform is dark, or to (re-)enroll the overlay identity without re-creating
 * the agent. An admin/MDM enrollment token may be passed instead of a session.
 */
export async function requestZitiEnrollmentJwt(
  enrollmentToken?: string,
): Promise<string> {
  const res = await api.post<{ ziti_enrollment_jwt: string; identity_name: string }>(
    `${BASE}/enroll`,
    enrollmentToken ? { enrollment_token: enrollmentToken } : {},
  );
  if (res.ziti_enrollment_jwt) {
    await SecureStore.setItemAsync(ZITI_JWT, res.ziti_enrollment_jwt);
  }
  return res.ziti_enrollment_jwt;
}

/** Report a device-posture snapshot. No-op (returns false) if not enrolled. */
export async function reportPosture(results: PostureResult[]): Promise<boolean> {
  const id = await getAgentIdentity();
  if (!id) return false;
  await api.post(
    `${BASE}/agent/report`,
    { agent_id: id.agentId, device_id: id.deviceId, results },
    { headers: { 'X-Agent-ID': id.agentId } },
  );
  return true;
}
