/**
 * Minimal, verification-free JWT payload decode. The server validates the
 * signature; the client only reads claims for UI (sub/email/name/roles/…).
 */
export type Claims = {
  sub?: string;
  email?: string;
  name?: string;
  preferred_username?: string;
  exp?: number;
  roles?: string[];
  groups?: string[];
  permissions?: string[];
};

function base64UrlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  // atob is available in the RN Hermes runtime; guard against a malformed
  // segment so a corrupt token never throws out of decodeClaims.
  const decode = (globalThis as { atob?: (s: string) => string }).atob;
  const bin = decode ? decode(b64) : '';
  try {
    // decode UTF-8 bytes
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return bin;
  }
}

/**
 * Decode a JWT's claims for UI display. This does NOT verify the signature — the
 * server does that on every request — so claims must never drive an
 * authorization decision on the client (the app has no client-side role gating;
 * the backend enforces access). We DO reject an expired token here so the UI
 * doesn't briefly treat a stale token as a live session before the API's
 * 401→refresh cycle catches it.
 */
export function decodeClaims(token: string | null | undefined): Claims | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const claims = JSON.parse(base64UrlDecode(parts[1])) as Claims;
    if (typeof claims.exp === 'number' && claims.exp * 1000 <= Date.now()) {
      // Expired: treat as no session. The auth provider/refresh path decides
      // whether a refresh token can revive it.
      return null;
    }
    return claims;
  } catch {
    return null;
  }
}
