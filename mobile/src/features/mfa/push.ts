/**
 * Push MFA — this device as an approval authenticator (number-matching).
 * Backend: internal/identity/pushmfa.go.
 *
 * MVP delivery is poll-based: real FCM/APNs delivery is a fast-follow, so until
 * then the device registers with a stable per-install id as the token
 * placeholder and challenges are opened by challenge_id (deep link
 * `openidx://approve/<id>` — the shape a future push notification will use).
 * The number-matching status endpoint redacts the code, so the user enters the
 * number shown on the other device; we submit it with the approve/deny verdict.
 */
import * as Crypto from 'expo-crypto';
import * as Device from 'expo-device';
import { Platform } from 'react-native';

import { api } from '@/lib/api';
import * as SecureStore from 'expo-secure-store';

const BASE = '/api/v1/identity/mfa/push';
const INSTALL_ID = 'oidx.install_id';

export type PushDevice = {
  id: string;
  platform: string;
  device_name: string;
  enabled: boolean;
  trusted: boolean;
  created_at: string;
};

export type PushChallengeStatus = {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  expires_at: string;
};

async function installId(): Promise<string> {
  let id = await SecureStore.getItemAsync(INSTALL_ID);
  if (!id) {
    id = Crypto.randomUUID();
    await SecureStore.setItemAsync(INSTALL_ID, id);
  }
  return id;
}

/** Register this device as a push authenticator (idempotent by install id). */
export async function registerDevice(): Promise<PushDevice> {
  return api.post<PushDevice>(`${BASE}/register`, {
    device_token: await installId(), // FCM/APNs token replaces this (fast-follow)
    platform: Platform.OS,
    device_name: Device.deviceName ?? `${Platform.OS} device`,
    device_model: Device.modelName ?? undefined,
    os_version: Device.osVersion ?? undefined,
  });
}

/**
 * Payload encoded in the "Enroll via Authenticator App" QR the admin console
 * shows (server: internal/identity/pushmfa_enroll.go). The user scans it and
 * this device binds itself as a push authenticator for that account — no
 * separate login for the target account required, because the single-use,
 * short-lived enrollment token is the authorization.
 */
export type PushEnrollQR = {
  type: 'openidx-push-enroll';
  api_base: string;
  token: string;
  account: string;
  issuer: string;
};

/** Recognize a scanned push-enrollment QR payload (JSON), else null. */
export function parsePushEnrollQR(data: string): PushEnrollQR | null {
  try {
    const p = JSON.parse(data) as Partial<PushEnrollQR>;
    if (p && p.type === 'openidx-push-enroll' && p.token && p.api_base) {
      return p as PushEnrollQR;
    }
  } catch {
    // not JSON / not our payload
  }
  return null;
}

/**
 * Complete a QR enrollment: bind THIS device to the account the ticket was
 * minted for. Posts to the public complete endpoint at the QR's api_base with
 * the ticket + this device's push token. No bearer token needed.
 */
export async function completeQrEnrollment(qr: PushEnrollQR): Promise<PushDevice> {
  const url = `${qr.api_base.replace(/\/$/, '')}/api/v1/identity/mfa/push/enroll/complete`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      enrollment_token: qr.token,
      device_token: await installId(),
      platform: Platform.OS,
      device_name: Device.deviceName ?? `${Platform.OS} device`,
      device_model: Device.modelName ?? undefined,
      os_version: Device.osVersion ?? undefined,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as PushDevice & { error?: string };
  if (!res.ok) {
    throw new Error(body.error || 'Enrollment failed');
  }
  return body;
}


export function listDevices(): Promise<PushDevice[]> {
  return api.get<PushDevice[]>(`${BASE}/devices`);
}

export function deleteDevice(id: string): Promise<void> {
  return api.delete<void>(`${BASE}/devices/${encodeURIComponent(id)}`);
}

export function getChallengeStatus(id: string): Promise<PushChallengeStatus> {
  return api.get<PushChallengeStatus>(
    `${BASE}/challenge/${encodeURIComponent(id)}`,
  );
}

/** Submit the number the user read off the other device, with the verdict. */
export function verifyChallenge(
  challengeId: string,
  challengeCode: string,
  approved: boolean,
): Promise<{ verified: boolean }> {
  return api.post<{ verified: boolean }>(`${BASE}/verify`, {
    challenge_id: challengeId,
    challenge_code: challengeCode,
    approved,
  });
}
