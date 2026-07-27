import { Link, Stack, useFocusEffect } from 'expo-router';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import {
  formatCode,
  generateHOTP,
  generateTOTP,
  secondsRemaining,
  type OtpAccount,
} from '@/features/authenticator/otp';
import { deleteAccount, listAccounts, updateAccount } from '@/features/authenticator/store';

/**
 * The authenticator home screen: a live list of one-time codes, exactly like
 * Google Authenticator / Microsoft Authenticator. TOTP rows refresh every
 * second with a shrinking countdown bar; HOTP rows advance on demand. All
 * computation is on-device — no network, no server round-trip.
 */
export default function AuthenticatorScreen() {
  const [accounts, setAccounts] = useState<OtpAccount[] | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const reload = useCallback(async () => {
    setAccounts(await listAccounts());
  }, []);

  // Reload whenever the screen regains focus (e.g. after adding an account).
  useFocusEffect(
    useCallback(() => {
      reload();
    }, [reload])
  );

  // One shared 1 Hz tick drives every row's code + countdown.
  useEffect(() => {
    timer.current = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  const remove = useCallback(
    (account: OtpAccount) => {
      Alert.alert(
        'Remove account',
        `Delete the code for ${account.issuer}${account.label ? ` (${account.label})` : ''}? ` +
          `You will need to re-add it from that service.`,
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Remove',
            style: 'destructive',
            onPress: async () => {
              await deleteAccount(account.id);
              reload();
            },
          },
        ]
      );
    },
    [reload]
  );

  const advanceHotp = useCallback(
    async (account: OtpAccount) => {
      const next = { ...account, counter: (account.counter ?? 0) + 1 };
      await updateAccount(next);
      reload();
    },
    [reload]
  );

  return (
    <>
      <Stack.Screen
        options={{
          title: 'Authenticator',
          headerRight: () => (
            <Link href="/(app)/authenticator/add" asChild>
              <Pressable hitSlop={12}>
                <Text style={styles.addBtn}>+ Add</Text>
              </Pressable>
            </Link>
          ),
        }}
      />
      {accounts === null ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : accounts.length === 0 ? (
        <ScrollView contentContainerStyle={styles.empty}>
          <Text style={styles.emptyTitle}>No codes yet</Text>
          <Text style={styles.emptyBody}>
            Add an account to generate the 6-digit verification codes for services like Google,
            GitHub, Microsoft, AWS and any site that supports authenticator-app 2FA.
          </Text>
          <Link href="/(app)/authenticator/add" asChild>
            <Pressable style={styles.emptyCta}>
              <Text style={styles.emptyCtaText}>Add your first account</Text>
            </Pressable>
          </Link>
        </ScrollView>
      ) : (
        <ScrollView contentContainerStyle={styles.list}>
          {accounts.map((a) => (
            <CodeRow
              key={a.id}
              account={a}
              now={now}
              onRemove={() => remove(a)}
              onAdvance={() => advanceHotp(a)}
            />
          ))}
          <Text style={styles.footer}>
            Codes are generated on this device from secrets stored in the secure keystore. They
            never leave your phone.
          </Text>
        </ScrollView>
      )}
    </>
  );
}

function CodeRow({
  account,
  now,
  onRemove,
  onAdvance,
}: {
  account: OtpAccount;
  now: number;
  onRemove: () => void;
  onAdvance: () => void;
}) {
  const isHotp = account.type === 'hotp';
  const code = isHotp
    ? generateHOTP(account.secret, account.counter ?? 0, account.digits, account.algorithm)
    : generateTOTP(account, now);
  const remaining = isHotp ? account.period : secondsRemaining(account.period, now);
  const fraction = isHotp ? 1 : remaining / account.period;
  const urgent = !isHotp && remaining <= 5;

  return (
    <Pressable style={styles.row} onLongPress={onRemove} delayLongPress={400}>
      <View style={styles.rowHeader}>
        <Text style={styles.issuer} numberOfLines={1}>
          {account.issuer}
        </Text>
        {!!account.label && account.label !== account.issuer && (
          <Text style={styles.label} numberOfLines={1}>
            {account.label}
          </Text>
        )}
      </View>
      <View style={styles.rowBody}>
        <Text style={[styles.code, urgent && styles.codeUrgent]}>{formatCode(code)}</Text>
        {isHotp ? (
          <Pressable style={styles.nextBtn} onPress={onAdvance} hitSlop={8}>
            <Text style={styles.nextBtnText}>Next ↻</Text>
          </Pressable>
        ) : (
          <Text style={[styles.remaining, urgent && styles.codeUrgent]}>{remaining}s</Text>
        )}
      </View>
      {!isHotp && (
        <View style={styles.progressTrack}>
          <View
            style={[
              styles.progressFill,
              { width: `${Math.max(0, Math.min(100, fraction * 100))}%` },
              urgent && styles.progressUrgent,
            ]}
          />
        </View>
      )}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  addBtn: { color: '#208AEF', fontSize: 16, fontWeight: '600' },
  list: { padding: 16, gap: 12 },
  row: {
    borderRadius: 16,
    padding: 16,
    backgroundColor: 'rgba(127,127,127,0.12)',
    gap: 10,
  },
  rowHeader: { gap: 2 },
  issuer: { fontSize: 16, fontWeight: '700' },
  label: { fontSize: 13, opacity: 0.6 },
  rowBody: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  code: {
    fontSize: 34,
    fontWeight: '700',
    letterSpacing: 2,
    fontVariant: ['tabular-nums'],
    color: '#208AEF',
  },
  codeUrgent: { color: '#E5484D' },
  remaining: { fontSize: 15, fontWeight: '600', opacity: 0.7, fontVariant: ['tabular-nums'] },
  nextBtn: {
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 10,
    backgroundColor: 'rgba(32,138,239,0.15)',
  },
  nextBtnText: { color: '#208AEF', fontWeight: '600' },
  progressTrack: {
    height: 4,
    borderRadius: 2,
    backgroundColor: 'rgba(127,127,127,0.2)',
    overflow: 'hidden',
  },
  progressFill: { height: 4, borderRadius: 2, backgroundColor: '#208AEF' },
  progressUrgent: { backgroundColor: '#E5484D' },
  footer: { fontSize: 12, opacity: 0.5, textAlign: 'center', marginTop: 8, paddingHorizontal: 8 },
  empty: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', padding: 32, gap: 14 },
  emptyTitle: { fontSize: 22, fontWeight: '700' },
  emptyBody: { fontSize: 15, opacity: 0.6, textAlign: 'center', lineHeight: 21 },
  emptyCta: {
    marginTop: 8,
    height: 50,
    paddingHorizontal: 28,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  emptyCtaText: { color: '#fff', fontSize: 16, fontWeight: '600' },
});
