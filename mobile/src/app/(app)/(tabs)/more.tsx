import { useQuery } from '@tanstack/react-query';
import { Link, type Href } from 'expo-router';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { unreadCount } from '@/features/notifications/api';
import { useAuth } from '@/lib/auth';

/**
 * "More" tab — everything that isn't the two primary tabs (codes / approvals):
 * the user's access, notifications, privileged-access (PAM), security settings,
 * and sign-out. Mirrors the overflow/settings tab in Microsoft Authenticator.
 */
export default function MoreScreen() {
  const { claims, logout } = useAuth();
  const name = claims?.name ?? claims?.preferred_username ?? claims?.email ?? 'there';

  const { data: unread } = useQuery({
    queryKey: ['notifications-unread'],
    queryFn: unreadCount,
    refetchInterval: 30000,
  });

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.greeting}>Hi, {name}</Text>
      <Text style={styles.sub}>You are signed in to OpenIDX.</Text>

      <Text style={styles.groupLabel}>Account</Text>
      <View style={styles.nav}>
        <NavRow href="/(app)/my-access" label="My Access" />
        <NavRow href="/(app)/notifications" label="Notifications" badge={unread} last />
      </View>

      <Text style={styles.groupLabel}>Privileged Access</Text>
      <View style={styles.nav}>
        <NavRow href="/(app)/pam" label="Connections" />
        <NavRow href="/(app)/pam/requests" label="My PAM requests" last />
      </View>

      <Text style={styles.groupLabel}>Security</Text>
      <View style={styles.nav}>
        <NavRow href="/(app)/security/passkeys" label="Passkeys" />
        <NavRow href="/(app)/security/totp" label="Authenticator app (OpenIDX 2FA)" />
        <NavRow href="/(app)/authenticator/backup" label="Back up / restore codes" />
        <NavRow href="/(app)/security/device" label="This device" last />
      </View>

      <Pressable style={styles.logout} onPress={logout}>
        <Text style={styles.logoutText}>Sign out</Text>
      </Pressable>
    </ScrollView>
  );
}

function NavRow({
  href,
  label,
  badge,
  last,
}: {
  href: Href;
  label: string;
  badge?: number;
  last?: boolean;
}) {
  return (
    <Link href={href} asChild>
      <Pressable style={[styles.navItem, last && styles.navItemLast]}>
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
  navItemLast: { borderBottomWidth: 0 },
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
    marginTop: 20,
    height: 52,
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'rgba(127,127,127,0.5)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoutText: { fontSize: 16, fontWeight: '600', color: '#d33' },
});
