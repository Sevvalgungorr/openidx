import { useMutation, useQuery } from '@tanstack/react-query';
import { Stack, useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import {
  getChallengeStatus,
  reportChallenge,
  verifyChallenge,
} from '@/features/mfa/push';

/**
 * Push approval with rich "additional context" (anti-MFA-fatigue): shows which
 * app requested the sign-in, from where (geo-located from the request IP
 * server-side — device GPS is spoofable), on what browser, and when, so the
 * user can spot a prompt they didn't trigger. Approving requires number
 * matching; a prompt you don't recognize can be denied as "This wasn't me"
 * without entering any number (which records a suspicious-activity signal).
 */
export default function ApprovePushScreen() {
  const { challengeId } = useLocalSearchParams<{ challengeId: string }>();
  const router = useRouter();
  const [code, setCode] = useState('');

  const status = useQuery({
    queryKey: ['push-challenge', challengeId],
    queryFn: () => getChallengeStatus(challengeId),
    enabled: !!challengeId,
    refetchInterval: 5000,
  });

  const verify = useMutation({
    mutationFn: (approved: boolean) =>
      verifyChallenge(challengeId, code.trim(), approved),
    onSuccess: (_r, approved) => {
      Alert.alert(approved ? 'Approved' : 'Denied');
      router.back();
    },
    onError: (e) =>
      Alert.alert('Failed', e instanceof Error ? e.message : String(e)),
  });

  const report = useMutation({
    mutationFn: () => reportChallenge(challengeId),
    onSuccess: () => {
      Alert.alert(
        'Reported',
        'Thanks — we\u2019ve flagged this sign-in as suspicious and denied it.',
      );
      router.back();
    },
    onError: (e) =>
      Alert.alert('Failed', e instanceof Error ? e.message : String(e)),
  });

  const st = status.data?.status;
  const settled =
    st === 'approved' || st === 'denied' || st === 'expired' || st === 'reported';
  const ctx = status.data?.context;

  const confirmReport = () =>
    Alert.alert(
      'This wasn\u2019t me?',
      'This will deny the sign-in and report it as suspicious.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Report',
          style: 'destructive',
          onPress: () => report.mutate(),
        },
      ],
    );

  return (
    <>
      <Stack.Screen options={{ title: 'Approve sign-in' }} />
      <View style={styles.container}>
        {status.isLoading ? (
          <ActivityIndicator />
        ) : settled ? (
          <Text style={styles.settled}>This request is {st}.</Text>
        ) : (
          <>
            <Text style={styles.prompt}>
              Are you trying to sign in
              {ctx?.app_name ? ` to ${ctx.app_name}` : ''}?
            </Text>

            {(ctx?.app_name ||
              ctx?.location ||
              ctx?.ip_address ||
              ctx?.browser) && (
              <View style={styles.ctxCard}>
                {ctx?.app_name ? (
                  <Row label="App" value={ctx.app_name} />
                ) : null}
                {ctx?.location ? (
                  <Row label="Location" value={ctx.location} />
                ) : null}
                {ctx?.ip_address ? (
                  <Row label="IP address" value={ctx.ip_address} />
                ) : null}
                {ctx?.browser ? (
                  <Row label="Browser" value={ctx.browser} />
                ) : null}
                {ctx?.created_at ? (
                  <Row
                    label="When"
                    value={new Date(ctx.created_at).toLocaleString()}
                  />
                ) : null}
              </View>
            )}

            <Text style={styles.hint}>
              If this is you, enter the number shown where you are signing in.
            </Text>
            <TextInput
              style={styles.input}
              value={code}
              onChangeText={setCode}
              keyboardType="number-pad"
              maxLength={2}
              placeholder="00"
            />
            <View style={styles.actions}>
              <Pressable
                style={[styles.btn, styles.deny]}
                disabled={verify.isPending || report.isPending}
                onPress={() => verify.mutate(false)}>
                <Text style={styles.denyText}>Deny</Text>
              </Pressable>
              <Pressable
                style={[styles.btn, styles.approve]}
                disabled={
                  verify.isPending ||
                  report.isPending ||
                  code.trim().length === 0
                }
                onPress={() => verify.mutate(true)}>
                <Text style={styles.approveText}>Approve</Text>
              </Pressable>
            </View>

            <Pressable
              style={styles.reportLink}
              disabled={report.isPending}
              onPress={confirmReport}>
              <Text style={styles.reportText}>This wasn&rsquo;t me</Text>
            </Pressable>
          </>
        )}
      </View>
    </>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue} numberOfLines={1}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, gap: 12, justifyContent: 'center' },
  prompt: { fontSize: 20, fontWeight: '700', textAlign: 'center' },
  hint: { fontSize: 15, opacity: 0.6, textAlign: 'center' },
  settled: { fontSize: 18, textAlign: 'center', opacity: 0.7 },
  ctxCard: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.25)',
    borderRadius: 14,
    padding: 14,
    gap: 8,
    marginVertical: 4,
  },
  row: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  rowLabel: { fontSize: 14, opacity: 0.6 },
  rowValue: { fontSize: 14, fontWeight: '600', flexShrink: 1, textAlign: 'right' },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 14,
    padding: 14,
    fontSize: 34,
    letterSpacing: 8,
    textAlign: 'center',
    marginVertical: 12,
  },
  actions: { flexDirection: 'row', gap: 12 },
  btn: {
    flex: 1,
    height: 52,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  approve: { backgroundColor: '#1a8f3c' },
  approveText: { color: 'white', fontSize: 17, fontWeight: '700' },
  deny: { borderWidth: 1, borderColor: '#d33' },
  denyText: { color: '#d33', fontSize: 17, fontWeight: '700' },
  reportLink: { alignItems: 'center', paddingVertical: 12 },
  reportText: { color: '#d33', fontSize: 15, fontWeight: '600' },
});
