/**
 * ntfy push subscription — real-time notifications without FCM/APNs.
 *
 * The backend derives a per-user secret topic on a self-hosted ntfy server
 * (see docs/NTFY_PUSH_NOTIFICATIONS.md). This hook fetches the subscription
 * details from `/notifications/push-config`, opens a WebSocket to
 * `{base}/{topic}/ws`, and surfaces each message as a local notification via
 * expo-notifications. Everything stays on your own infrastructure — no
 * Google/Apple push services in the path.
 *
 * Lifecycle: connected while the app is in the foreground; closed in the
 * background (RN sockets are frozen there anyway). On return to foreground it
 * reconnects with ntfy's `since=` parameter so messages that arrived while
 * away are caught up and shown. Reconnects use capped exponential backoff and
 * everything is best-effort — push is an accelerator on top of the in-app
 * notification list, never a source of truth.
 */
import * as Notifications from 'expo-notifications';
import { useRouter } from 'expo-router';
import { useEffect, useRef } from 'react';
import { AppState, Platform } from 'react-native';
import { useQuery } from '@tanstack/react-query';

import { getPushConfig } from './api';

// Show ntfy-driven notifications while the app is foregrounded too (default
// on iOS would silently drop them).
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowBanner: true,
    shouldShowList: true,
    shouldPlaySound: true,
    shouldSetBadge: false,
  }),
});

/** One parsed ntfy stream event (only `message` events carry content). */
type NtfyEvent = {
  id?: string;
  time?: number;
  event?: string;
  title?: string;
  message?: string;
  click?: string;
};

function wsUrl(baseURL: string, topic: string, sinceUnix: number | null): string {
  const base = baseURL.replace(/\/+$/, '').replace(/^http/, 'ws');
  const since = sinceUnix ? `?since=${sinceUnix}` : '';
  return `${base}/${topic}/ws${since}`;
}

const MAX_BACKOFF_MS = 60_000;

/**
 * Subscribe the signed-in user to their ntfy topic. Mount once inside the
 * authenticated app group; it no-ops when the server has no ntfy configured
 * (push-config `enabled:false`) and on web.
 */
export function useNtfyPush() {
  const router = useRouter();

  const { data: cfg } = useQuery({
    queryKey: ['push-config'],
    queryFn: getPushConfig,
    staleTime: 5 * 60_000,
    enabled: Platform.OS !== 'web',
  });

  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(1000);
  // Unix time of the newest message seen; reconnects replay from here so
  // backgrounded time doesn't lose notifications.
  const lastSeenRef = useRef<number | null>(null);
  const stoppedRef = useRef(false);

  useEffect(() => {
    if (Platform.OS === 'web' || !cfg?.enabled || !cfg.base_url || !cfg.topic) return;
    const { base_url: baseURL, topic } = cfg;
    stoppedRef.current = false;

    // Android needs a channel before anything can be displayed; permission
    // prompt is a no-op if already granted/denied.
    (async () => {
      await Notifications.requestPermissionsAsync();
      if (Platform.OS === 'android') {
        await Notifications.setNotificationChannelAsync('default', {
          name: 'OpenIDX',
          importance: Notifications.AndroidImportance.HIGH,
        });
      }
    })();

    const closeSocket = () => {
      if (retryRef.current) {
        clearTimeout(retryRef.current);
        retryRef.current = null;
      }
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws) {
        // Detach handlers first so the close doesn't schedule a reconnect.
        ws.onclose = null;
        ws.onerror = null;
        ws.onmessage = null;
        try {
          ws.close();
        } catch {
          // already closed
        }
      }
    };

    const connect = () => {
      if (stoppedRef.current || wsRef.current) return;
      const ws = new WebSocket(wsUrl(baseURL, topic, lastSeenRef.current));
      wsRef.current = ws;

      ws.onopen = () => {
        backoffRef.current = 1000;
      };
      ws.onmessage = (ev) => {
        let msg: NtfyEvent;
        try {
          msg = JSON.parse(String(ev.data)) as NtfyEvent;
        } catch {
          return;
        }
        if (msg.time) lastSeenRef.current = msg.time;
        if (msg.event !== 'message' || !msg.message) return; // open/keepalive
        void Notifications.scheduleNotificationAsync({
          content: {
            title: msg.title || 'OpenIDX',
            body: msg.message,
            data: { click: msg.click ?? null },
          },
          trigger: null, // immediately
        });
      };
      const scheduleReconnect = () => {
        if (stoppedRef.current) return;
        wsRef.current = null;
        if (retryRef.current) clearTimeout(retryRef.current);
        retryRef.current = setTimeout(connect, backoffRef.current);
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
      };
      ws.onerror = scheduleReconnect;
      ws.onclose = scheduleReconnect;
    };

    connect();

    // Foreground-only subscription: close in background, reconnect (with
    // since= catch-up) when the app becomes active again.
    const appState = AppState.addEventListener('change', (s) => {
      if (s === 'active') {
        connect();
      } else if (s === 'background') {
        closeSocket();
      }
    });

    // Tapping a notification opens the in-app notification list (the message
    // itself is already persisted server-side on the in_app channel).
    const tap = Notifications.addNotificationResponseReceivedListener(() => {
      router.push('/notifications');
    });

    return () => {
      stoppedRef.current = true;
      appState.remove();
      tap.remove();
      closeSocket();
    };
  }, [cfg, router]);
}
