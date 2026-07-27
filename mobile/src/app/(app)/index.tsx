import { useQuery } from '@tanstack/react-query';
import { Link, Stack, type Href } from 'expo-router';
import { useEffect } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { listPendingApprovals } from '@/features/approvals/api';
import { registerDevice } from '@/features/mfa/push';
import { unreadCount } from '@/features/notifications/api';
import { useAuth } from '@/lib/auth';

function NavRow({
  href,
  label,
  badge,
}: {
  href: Href;
  label: string;
  badge?: number;
}) {
  return (
    <Link href={href} asChild>
      <Pressable style={styles.navItem}>
        <Text style={styles.navText}>{label}</Text>
        <View style={styles.navRight}>
          {!!badge && (
            <View style={styles.badge}>
              <Text style={styles.badgeText}>{badge}</Text>
            </View>
          )}
          <Text style={styles.navChevron}>›</Text>
        </View>
      </Pressable>
    </Link>
  );
}

export default function HomeScreen() {
  const { claims, logout } = useAuth();
  const name = claims?.name ?? claims?.preferred_username ?? claims?.email ?? 'there';

  // Register this device as a push authenticator (best-effort, idempotent).
  useEffect(() => {
    registerDevice().catch(() => {});
  }, []);

  const { data: unread } = useQuery({
    queryKey: ['notifications-unread'],
    queryFn: unreadCount,
    refetchInterval: 30000,
  });
  const { data: pending } = useQuery({
    queryKey: ['approvals'],
    queryFn: listPendingApprovals,
    refetchInterval: 30000,
    select: (r) => r.length,
  });

  return (
    <>
      <Stack.Screen options={{ title: 'OpenIDX' }} />
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.greeting}>Hi, {name}</Text>
        <Text style={styles.sub}>You are signed in.</Text>

        <View style={styles.nav}>
          <NavRow href="/(app)/authenticator" label="Authenticator" />
          <NavRow href="/(app)/approvals" label="Approvals" badge={pending} />
          <NavRow href="/(app)/my-access" label="My Access" />
          <NavRow href="/(app)/notifications" label="Notifications" badge={unread} />
        </View>

        <Text style={styles.groupLabel}>Privileged Access</Text>
        <View style={styles.nav}>
          <NavRow href="/(app)/pam" label="Connections" />
          <NavRow href="/(app)/pam/requests" label="My PAM requests" />
        </View>

        <Text style={styles.groupLabel}>Security</Text>
        <View style={styles.nav}>
          <NavRow href="/(app)/security/passkeys" label="Passkeys" />
          <NavRow href="/(app)/security/totp" label="Authenticator app" />
          <NavRow href="/(app)/security/device" label="This device" />
        </View>

        <Pressable style={styles.logout} onPress={logout}>
          <Text style={styles.logoutText}>Sign out</Text>
        </Pressable>
      </ScrollView>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 12 },
  greeting: { fontSize: 28, fontWeight: '700' },
  sub: { fontSize: 15, opacity: 0.6, marginBottom: 4 },
  groupLabel: {
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.5,
    marginTop: 8,
    marginLeft: 4,
  },
  nav: { borderRadius: 14, overflow: 'hidden', backgroundColor: 'rgba(127,127,127,0.12)' },
  navItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.25)',
  },
  navText: { fontSize: 16, fontWeight: '500' },
  navRight: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  navChevron: { fontSize: 22, opacity: 0.4 },
  badge: {
    minWidth: 22,
    height: 22,
    borderRadius: 11,
    paddingHorizontal: 6,
    backgroundColor: '#d33',
    alignItems: 'center',
    justifyContent: 'center',
  },
  badgeText: { color: 'white', fontSize: 12, fontWeight: '700' },
  logout: {
    height: 48,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#d33',
    marginTop: 16,
  },
  logoutText: { color: '#d33', fontSize: 16, fontWeight: '600' },
});
