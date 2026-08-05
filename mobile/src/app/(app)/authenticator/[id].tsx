import { Stack, useLocalSearchParams, useRouter } from 'expo-router';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';

import { IssuerAvatar } from '@/components/authenticator/account-visuals';
import { buildOtpauthUri, formatCode, generateTOTP, type OtpAccount } from '@/features/authenticator/otp';
import { deleteAccount, getAccount, updateAccount } from '@/features/authenticator/store';

/**
 * Account detail — the screen you reach by tapping a code's chevron. It mirrors
 * Microsoft Authenticator's account page: rename the account, reveal a QR code
 * (and setup key) so you can move it to another authenticator, and remove it.
 * The QR encodes the standard otpauth:// URI, so any authenticator app can scan
 * it — this is OpenIDX *producing* the same QR a service shows during 2FA setup.
 */
export default function AccountDetailScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const [account, setAccount] = useState<OtpAccount | null | undefined>(undefined);
  const [showSecret, setShowSecret] = useState(false);
  const [showQr, setShowQr] = useState(false);
  const [editing, setEditing] = useState(false);
  const [issuer, setIssuer] = useState('');
  const [label, setLabel] = useState('');

  useEffect(() => {
    getAccount(id).then((a) => {
      setAccount(a);
      if (a) {
        setIssuer(a.issuer);
        setLabel(a.label);
      }
    });
  }, [id]);

  const copySecret = useCallback(async () => {
    if (!account) return;
    await Clipboard.setStringAsync(account.secret);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    Alert.alert('Copied', 'The setup key was copied to your clipboard.');
  }, [account]);

  const saveRename = useCallback(async () => {
    if (!account) return;
    const nextIssuer = issuer.trim() || account.issuer;
    const next = { ...account, issuer: nextIssuer, label: label.trim() || nextIssuer };
    await updateAccount(next);
    setAccount(next);
    setEditing(false);
  }, [account, issuer, label]);

  const remove = useCallback(() => {
    if (!account) return;
    Alert.alert(
      'Remove account',
      `Delete the code for ${account.issuer}${account.label && account.label !== account.issuer ? ` (${account.label})` : ''}? ` +
        `You will need to re-add it from that service.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Remove',
          style: 'destructive',
          onPress: async () => {
            await deleteAccount(account.id);
            router.back();
          },
        },
      ]
    );
  }, [account, router]);

  if (account === undefined) {
    return <ActivityIndicator style={{ marginTop: 40 }} />;
  }
  if (account === null) {
    return (
      <View style={styles.missing}>
        <Text style={styles.missingText}>This account no longer exists.</Text>
      </View>
    );
  }

  const uri = buildOtpauthUri(account);
  const previewCode = account.type === 'totp' ? formatCode(generateTOTP(account)) : '— — —';

  return (
    <>
      <Stack.Screen options={{ title: account.issuer }} />
      <ScrollView contentContainerStyle={styles.container}>
        {/* Identity header */}
        <View style={styles.header}>
          <IssuerAvatar issuer={account.issuer} size={64} />
          {editing ? (
            <View style={styles.editFields}>
              <Text style={styles.fieldLabel}>Service name</Text>
              <TextInput style={styles.input} value={issuer} onChangeText={setIssuer} autoCapitalize="words" />
              <Text style={styles.fieldLabel}>Account</Text>
              <TextInput style={styles.input} value={label} onChangeText={setLabel} autoCapitalize="none" autoCorrect={false} />
              <View style={styles.editActions}>
                <Pressable style={[styles.smallBtn, styles.smallBtnGhost]} onPress={() => setEditing(false)}>
                  <Text style={styles.smallBtnGhostText}>Cancel</Text>
                </Pressable>
                <Pressable style={styles.smallBtn} onPress={saveRename}>
                  <Text style={styles.smallBtnText}>Save</Text>
                </Pressable>
              </View>
            </View>
          ) : (
            <View style={styles.headerText}>
              <Text style={styles.issuer}>{account.issuer}</Text>
              {!!account.label && account.label !== account.issuer && (
                <Text style={styles.label}>{account.label}</Text>
              )}
              <Text style={styles.meta}>
                {account.type.toUpperCase()} · {account.digits} digits · {account.algorithm}
                {account.type === 'totp' ? ` · ${account.period}s` : ''}
              </Text>
            </View>
          )}
        </View>

        {!editing && (
          <>
            <View style={styles.previewCard}>
              <Text style={styles.previewLabel}>Current code</Text>
              <Text style={styles.previewCode}>{previewCode}</Text>
            </View>

            {/* Actions */}
            <View style={styles.actions}>
              <ActionRow icon="✏️" label="Rename" onPress={() => setEditing(true)} />
              <ActionRow
                icon="🔳"
                label={showQr ? 'Hide QR code' : 'Show QR code (move to another app)'}
                onPress={() => setShowQr((v) => !v)}
              />
              <ActionRow
                icon="🔑"
                label={showSecret ? 'Hide setup key' : 'Show setup key'}
                onPress={() => setShowSecret((v) => !v)}
              />
            </View>

            {showQr && (
              <View style={styles.qrCard}>
                <View style={styles.qrBox}>
                  <QRCode value={uri} size={220} />
                </View>
                <Text style={styles.qrHelp}>
                  Scan this with another authenticator app to add the same account there. The QR
                  contains the account secret — only show it to a device you trust.
                </Text>
              </View>
            )}

            {showSecret && (
              <Pressable style={styles.secretCard} onPress={copySecret}>
                <Text style={styles.secretLabel}>Setup key (tap to copy)</Text>
                <Text style={styles.secretValue} selectable>
                  {account.secret.replace(/(.{4})/g, '$1 ').trim()}
                </Text>
              </Pressable>
            )}

            <Pressable style={styles.deleteBtn} onPress={remove}>
              <Text style={styles.deleteText}>Remove account</Text>
            </Pressable>
          </>
        )}
      </ScrollView>
    </>
  );
}

function ActionRow({ icon, label, onPress }: { icon: string; label: string; onPress: () => void }) {
  return (
    <Pressable style={styles.actionRow} onPress={onPress}>
      <Text style={styles.actionIcon}>{icon}</Text>
      <Text style={styles.actionLabel}>{label}</Text>
      <Text style={styles.actionChevron}>›</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 16 },
  header: { flexDirection: 'row', gap: 16, alignItems: 'center' },
  headerText: { flex: 1, gap: 2 },
  issuer: { fontSize: 22, fontWeight: '700' },
  label: { fontSize: 15, opacity: 0.6 },
  meta: { fontSize: 12, opacity: 0.45, marginTop: 4 },
  editFields: { flex: 1, gap: 6 },
  fieldLabel: { fontSize: 12, fontWeight: '600', opacity: 0.6 },
  input: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 9,
    fontSize: 15,
    backgroundColor: 'rgba(127,127,127,0.06)',
  },
  editActions: { flexDirection: 'row', gap: 8, marginTop: 4 },
  smallBtn: {
    flex: 1,
    height: 40,
    borderRadius: 10,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  smallBtnText: { color: '#fff', fontWeight: '600' },
  smallBtnGhost: { backgroundColor: 'rgba(127,127,127,0.12)' },
  smallBtnGhostText: { fontWeight: '600', opacity: 0.7 },
  previewCard: {
    backgroundColor: 'rgba(37,99,235,0.08)',
    borderRadius: 16,
    padding: 18,
    alignItems: 'center',
    gap: 4,
  },
  previewLabel: { fontSize: 12, opacity: 0.55, fontWeight: '600' },
  previewCode: {
    fontSize: 34,
    fontWeight: '800',
    letterSpacing: 3,
    color: '#2563EB',
    fontVariant: ['tabular-nums'],
  },
  actions: { backgroundColor: 'rgba(127,127,127,0.06)', borderRadius: 16, overflow: 'hidden' },
  actionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 16,
    paddingVertical: 15,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.15)',
  },
  actionIcon: { fontSize: 18 },
  actionLabel: { flex: 1, fontSize: 15, fontWeight: '500' },
  actionChevron: { fontSize: 22, opacity: 0.3 },
  qrCard: { alignItems: 'center', gap: 12, padding: 8 },
  qrBox: { backgroundColor: '#fff', padding: 16, borderRadius: 16 },
  qrHelp: { fontSize: 13, opacity: 0.55, textAlign: 'center', lineHeight: 19, paddingHorizontal: 8 },
  secretCard: {
    backgroundColor: 'rgba(127,127,127,0.08)',
    borderRadius: 14,
    padding: 16,
    gap: 6,
  },
  secretLabel: { fontSize: 12, fontWeight: '600', opacity: 0.55 },
  secretValue: { fontSize: 18, fontWeight: '600', letterSpacing: 1, fontVariant: ['tabular-nums'] },
  deleteBtn: {
    height: 50,
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#DC2626',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 4,
  },
  deleteText: { color: '#DC2626', fontSize: 16, fontWeight: '600' },
  missing: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 32 },
  missingText: { fontSize: 16, opacity: 0.6 },
});
