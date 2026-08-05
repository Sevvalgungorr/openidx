import { Link, useFocusEffect, useNavigation, useRouter } from 'expo-router';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { CountdownRing, IssuerAvatar } from '@/components/authenticator/account-visuals';
import {
  formatCode,
  generateHOTP,
  generateTOTP,
  secondsRemaining,
  type OtpAccount,
} from '@/features/authenticator/otp';
import { listAccounts, updateAccount } from '@/features/authenticator/store';

/**
 * The authenticator home screen — a live list of one-time codes styled like
 * Microsoft Authenticator: a colored issuer tile, the big grouped code, a
 * one-tap copy, and a circular countdown. Tapping a row copies the code; the
 * chevron opens the account's detail screen (rename / QR export / delete).
 * All computation is on-device — no network, no server round-trip.
 */
export default function AuthenticatorScreen() {
  const router = useRouter();
  const navigation = useNavigation();
  const [accounts, setAccounts] = useState<OtpAccount[] | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [query, setQuery] = useState('');
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Put the "+ Add" action in the tab's header (Tabs manage the header, so we
  // set it imperatively rather than with a <Stack.Screen>).
  useLayoutEffect(() => {
    navigation.setOptions({
      headerRight: () => (
        <Link href="/(app)/authenticator/add" asChild>
          <Pressable hitSlop={12} style={{ paddingHorizontal: 12 }}>
            <Text style={styles.addBtn}>+ Add</Text>
          </Pressable>
        </Link>
      ),
    });
  }, [navigation]);

  const reload = useCallback(async () => {
    setAccounts(await listAccounts());
  }, []);

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

  const advanceHotp = useCallback(
    async (account: OtpAccount) => {
      const next = { ...account, counter: (account.counter ?? 0) + 1 };
      await updateAccount(next);
      reload();
    },
    [reload]
  );

  const filtered = useMemo(() => {
    if (!accounts) return null;
    const q = query.trim().toLowerCase();
    if (!q) return accounts;
    return accounts.filter(
      (a) =>
        a.issuer.toLowerCase().includes(q) || (a.label ?? '').toLowerCase().includes(q)
    );
  }, [accounts, query]);

  return (
    <>
      {accounts === null ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : accounts.length === 0 ? (
        <ScrollView contentContainerStyle={styles.empty}>
          <IssuerAvatar issuer="OpenIDX" size={72} />
          <Text style={styles.emptyTitle}>No codes yet</Text>
          <Text style={styles.emptyBody}>
            Add an account to generate 6-digit verification codes for services like Google,
            GitHub, Microsoft, AWS and any site that supports authenticator-app 2FA.
          </Text>
          <Link href="/(app)/authenticator/add" asChild>
            <Pressable style={styles.emptyCta}>
              <Text style={styles.emptyCtaText}>Add your first account</Text>
            </Pressable>
          </Link>
        </ScrollView>
      ) : (
        <ScrollView
          contentContainerStyle={styles.list}
          keyboardShouldPersistTaps="handled"
          keyboardDismissMode="on-drag"
        >
          {accounts.length >= 5 && (
            <TextInput
              style={styles.search}
              placeholder="Search accounts"
              placeholderTextColor="rgba(127,127,127,0.6)"
              value={query}
              onChangeText={setQuery}
              autoCapitalize="none"
              autoCorrect={false}
              returnKeyType="search"
            />
          )}
          {filtered && filtered.length === 0 ? (
            <Text style={styles.noMatch}>No accounts match “{query}”.</Text>
          ) : (
            filtered!.map((a) => (
              <CodeRow
                key={a.id}
                account={a}
                now={now}
                onOpen={() => router.push(`/(app)/authenticator/${a.id}`)}
                onAdvance={() => advanceHotp(a)}
              />
            ))
          )}
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
  onOpen,
  onAdvance,
}: {
  account: OtpAccount;
  now: number;
  onOpen: () => void;
  onAdvance: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const isHotp = account.type === 'hotp';
  const code = isHotp
    ? generateHOTP(account.secret, account.counter ?? 0, account.digits, account.algorithm)
    : generateTOTP(account, now);
  const remaining = isHotp ? account.period : secondsRemaining(account.period, now);

  const copy = useCallback(async () => {
    await Clipboard.setStringAsync(code);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }, [code]);

  return (
    <View style={styles.row}>
      <Pressable style={styles.rowMain} onPress={copy} accessibilityRole="button">
        <IssuerAvatar issuer={account.issuer} />
        <View style={styles.rowText}>
          <Text style={styles.issuer} numberOfLines={1}>
            {account.issuer}
          </Text>
          {!!account.label && account.label !== account.issuer && (
            <Text style={styles.label} numberOfLines={1}>
              {account.label}
            </Text>
          )}
          <Text style={[styles.code, copied && styles.codeCopied]}>
            {copied ? 'Copied' : formatCode(code)}
          </Text>
        </View>
        {isHotp ? (
          <Pressable style={styles.hotpBtn} onPress={onAdvance} hitSlop={8}>
            <Text style={styles.hotpBtnText}>↻</Text>
          </Pressable>
        ) : (
          <CountdownRing remaining={remaining} period={account.period} />
        )}
      </Pressable>
      <Pressable style={styles.chevronHit} onPress={onOpen} hitSlop={8} accessibilityLabel="Account details">
        <Text style={styles.chevron}>›</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  addBtn: { color: '#208AEF', fontSize: 16, fontWeight: '600' },
  list: { padding: 16, gap: 10 },
  search: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 15,
    backgroundColor: 'rgba(127,127,127,0.06)',
    marginBottom: 2,
  },
  noMatch: { textAlign: 'center', opacity: 0.5, marginTop: 16, fontSize: 14 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(127,127,127,0.06)',
    borderRadius: 16,
    paddingRight: 6,
  },
  rowMain: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    padding: 12,
  },
  rowText: { flex: 1, gap: 1 },
  issuer: { fontSize: 16, fontWeight: '600' },
  label: { fontSize: 13, opacity: 0.55 },
  code: {
    fontSize: 26,
    fontWeight: '700',
    letterSpacing: 2,
    fontVariant: ['tabular-nums'],
    marginTop: 2,
    color: '#2563EB',
  },
  codeCopied: { color: '#16A34A' },
  hotpBtn: {
    width: 40,
    height: 40,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(37,99,235,0.12)',
  },
  hotpBtnText: { fontSize: 20, color: '#2563EB' },
  chevronHit: { paddingHorizontal: 8, paddingVertical: 20 },
  chevron: { fontSize: 26, opacity: 0.35 },
  footer: { fontSize: 12, opacity: 0.45, lineHeight: 18, marginTop: 8, paddingHorizontal: 4 },
  empty: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', padding: 32, gap: 14 },
  emptyTitle: { fontSize: 22, fontWeight: '700', marginTop: 6 },
  emptyBody: { fontSize: 15, opacity: 0.6, textAlign: 'center', lineHeight: 21 },
  emptyCta: {
    marginTop: 8,
    height: 52,
    paddingHorizontal: 28,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  emptyCtaText: { color: '#fff', fontSize: 16, fontWeight: '600' },
});
