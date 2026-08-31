import { Link } from 'expo-router';
import Constants from 'expo-constants';
import { useEffect, useState } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet, Switch, Text, View } from 'react-native';

import { API_BASE_URL } from '@/config';
import { useAuth } from '@/lib/auth';
import {
  DEFAULT_SETTINGS,
  getSettings,
  updateSettings,
  type AppSettings,
  type LockTimeout,
} from '@/features/settings/store';

/**
 * Settings — the app's preferences hub, matching what Microsoft Authenticator
 * exposes (app lock, code privacy) plus the OpenIDX-specific facts a user of an
 * enterprise IdP app expects to see: which server they're bound to, who they're
 * signed in as, and shortcuts to device/security management and backup.
 */
export default function SettingsScreen() {
  const { claims, logout } = useAuth();
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    getSettings().then((s) => {
      setSettings(s);
      setLoaded(true);
    });
  }, []);

  const patch = async (p: Partial<AppSettings>) => {
    const next = await updateSettings(p);
    setSettings(next);
  };

  const account =
    claims?.name ?? claims?.preferred_username ?? claims?.email ?? 'Signed in';
  const server = API_BASE_URL.replace(/^https?:\/\//, '');
  const version =
    Constants.expoConfig?.version ??
    (Constants.expoConfig as { version?: string } | null)?.version ??
    '—';

  const lockOptions: { value: LockTimeout; label: string }[] = [
    { value: 'immediately', label: 'Immediately' },
    { value: '1m', label: 'After 1 minute' },
    { value: '5m', label: 'After 5 minutes' },
  ];

  return (
    <ScrollView contentContainerStyle={styles.container}>
        {/* Account / server (OpenIDX-specific) */}
        <Section title="Account">
          <InfoRow label="Signed in as" value={account} />
          <InfoRow label="Server" value={server} last />
        </Section>

        {/* Security */}
        <Section title="Security">
          <Text style={styles.subLabel}>App lock</Text>
          <View style={styles.segment}>
            {lockOptions.map((o) => (
              <Pressable
                key={o.value}
                style={[styles.segmentBtn, settings.lockTimeout === o.value && styles.segmentBtnActive]}
                onPress={() => patch({ lockTimeout: o.value })}
                disabled={!loaded}
              >
                <Text
                  style={[
                    styles.segmentText,
                    settings.lockTimeout === o.value && styles.segmentTextActive,
                  ]}
                >
                  {o.label}
                </Text>
              </Pressable>
            ))}
          </View>
          <Text style={styles.hint}>
            Require Face ID / Touch ID / device passcode after the app has been in the background
            this long.
          </Text>

          <ToggleRow
            label="Hide codes until tapped"
            value={settings.hideCodes}
            onValueChange={(v) => patch({ hideCodes: v })}
            disabled={!loaded}
          />
          <ToggleRow
            label="Tap a code to copy"
            value={settings.tapToCopy}
            onValueChange={(v) => patch({ tapToCopy: v })}
            disabled={!loaded}
            last
          />
        </Section>

        {/* Authenticator management */}
        <Section title="Authenticator">
          <NavRow href="/(app)/authenticator/backup" label="Back up / restore codes" />
          <NavRow href="/(app)/authenticator/add" label="Add an account" last />
        </Section>

        {/* OpenIDX workspace (enterprise features) */}
        <Section title="My workspace">
          <NavRow href="/(app)/my-access" label="My Access" />
          <NavRow href="/(app)/notifications" label="Notifications" />
          <NavRow href="/(app)/pam" label="Privileged connections" />
          <NavRow href="/(app)/pam/requests" label="My PAM requests" last />
        </Section>

        {/* OpenIDX security / device */}
        <Section title="Device & sign-in">
          <NavRow href="/(app)/security/passkeys" label="Passkeys" />
          <NavRow href="/(app)/security/totp" label="OpenIDX 2FA (authenticator app)" />
          <NavRow href="/(app)/security/device" label="This device & posture" last />
        </Section>

        <Section title="About">
          <InfoRow label="App version" value={String(version)} last />
        </Section>

        <Pressable
          style={styles.logout}
          onPress={() =>
            Alert.alert('Sign out', 'Sign out of OpenIDX on this device?', [
              { text: 'Cancel', style: 'cancel' },
              { text: 'Sign out', style: 'destructive', onPress: () => logout() },
            ])
          }
        >
          <Text style={styles.logoutText}>Sign out</Text>
        </Pressable>
    </ScrollView>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      <View style={styles.card}>{children}</View>
    </View>
  );
}

function InfoRow({ label, value, last }: { label: string; value: string; last?: boolean }) {
  return (
    <View style={[styles.row, last && styles.rowLast]}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue} numberOfLines={1}>
        {value}
      </Text>
    </View>
  );
}

function ToggleRow({
  label,
  value,
  onValueChange,
  disabled,
  last,
}: {
  label: string;
  value: boolean;
  onValueChange: (v: boolean) => void;
  disabled?: boolean;
  last?: boolean;
}) {
  return (
    <View style={[styles.row, last && styles.rowLast]}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Switch value={value} onValueChange={onValueChange} disabled={disabled} />
    </View>
  );
}

function NavRow({ href, label, last }: { href: string; label: string; last?: boolean }) {
  return (
    <Link href={href as never} asChild>
  <Pressable style={StyleSheet.flatten([styles.row, last && styles.rowLast])}>
        <Text style={styles.rowLabel}>{label}</Text>
        <Text style={styles.chevron}>›</Text>
      </Pressable>
    </Link>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 8, paddingBottom: 40 },
  section: { gap: 6, marginTop: 10 },
  sectionTitle: {
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.5,
    marginLeft: 4,
  },
  card: { borderRadius: 14, overflow: 'hidden', backgroundColor: 'rgba(127,127,127,0.1)' },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.2)',
    gap: 12,
  },
  rowLast: { borderBottomWidth: 0 },
  rowLabel: { fontSize: 15, fontWeight: '500', flexShrink: 1 },
  rowValue: { fontSize: 14, opacity: 0.6, maxWidth: '55%' },
  chevron: { fontSize: 22, opacity: 0.3 },
  subLabel: { fontSize: 13, fontWeight: '600', opacity: 0.6, paddingHorizontal: 16, paddingTop: 12 },
  segment: {
    flexDirection: 'row',
    gap: 6,
    padding: 12,
    paddingTop: 8,
  },
  segmentBtn: {
    flex: 1,
    paddingVertical: 9,
    borderRadius: 9,
    alignItems: 'center',
    backgroundColor: 'rgba(127,127,127,0.14)',
  },
  segmentBtnActive: { backgroundColor: '#2563EB' },
  segmentText: { fontSize: 12, fontWeight: '600', opacity: 0.75 },
  segmentTextActive: { color: '#fff', opacity: 1 },
  hint: { fontSize: 12, opacity: 0.5, lineHeight: 17, paddingHorizontal: 16, paddingBottom: 12 },
  logout: {
    marginTop: 24,
    height: 52,
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#DC2626',
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoutText: { fontSize: 16, fontWeight: '600', color: '#DC2626' },
});
