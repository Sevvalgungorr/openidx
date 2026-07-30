/**
 * In-app notifications. Backend: internal/notifications/service.go
 * (mounted under /api/v1/identity).
 */
import { api } from '@/lib/api';

const BASE = '/api/v1/identity/notifications';

export type Notification = {
  id: string;
  channel: string;
  type: string;
  title: string;
  body: string;
  link?: string | null;
  read: boolean;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export async function listNotifications(unreadOnly = false): Promise<Notification[]> {
  const r = await api.get<{ notifications: Notification[] }>(
    `${BASE}?limit=50${unreadOnly ? '&unread=true' : ''}`,
  );
  return r.notifications ?? [];
}

export async function unreadCount(): Promise<number> {
  const r = await api.get<{ unread_count: number }>(`${BASE}/unread-count`);
  return r.unread_count ?? 0;
}

export function markRead(ids: string[]): Promise<unknown> {
  return api.post(`${BASE}/mark-read`, { notification_ids: ids });
}

export function markAllRead(): Promise<unknown> {
  return api.post(`${BASE}/mark-all-read`, {});
}

/**
 * Push (ntfy) subscription details for the signed-in user. `topic` is a
 * per-user capability derived server-side (HMAC of the user id) — treat it
 * like a secret. `enabled:false` means the server has no ntfy configured.
 */
export type PushConfig = {
  enabled: boolean;
  base_url?: string;
  topic?: string;
};

export function getPushConfig(): Promise<PushConfig> {
  return api.get<PushConfig>(`${BASE}/push-config`);
}
