import { Link, Stack, useRouter } from 'expo-router';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import { useState } from 'react';
import {
  Alert,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';

import { isValidBase32 } from '@/features/authenticator/crypto';
import {
  buildOtpauthUri,
  generateSecret,
  generateTOTP,
  parseOtpauthUri,
  type OtpAccount,
  type OtpAlgorithm,
} from '@/features/authenticator/otp';
import { addAccount } from '@/features/authenticator/store';

type Mode = 'uri' | 'manual' | 'create';

/**
 * Add-account screen. Three paths:
 *  - "Scan / paste setup key": paste an otpauth:// URI (what a QR encodes).
 *  - "Enter manually": type issuer/account/secret from a "can't scan?" screen.
 *  - "Create in OpenIDX": OpenIDX *generates* a fresh secret and shows its QR +
 *    setup key so you can register it with a service — the same thing a website
 *    does when it presents a 2FA QR, but produced here.
 *
 * The secret is validated by generating a code before saving, so a mistyped key
 * is caught immediately rather than silently producing wrong codes.
 */
export default function AddAccountScreen() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('uri');

  const [uri, setUri] = useState('');
  const [issuer, setIssuer] = useState('');
  const [label, setLabel] = useState('');
  const [secret, setSecret] = useState('');

  const save = async (input: Omit<OtpAccount, 'id' | 'createdAt'>) => {
    try {
      generateTOTP({ ...input, id: 'preview', createdAt: 0 });
    } catch {
      Alert.alert('Invalid secret', 'That secret key could not be used to generate a code.');
      return;
    }
    await addAccount(input);
    router.back();
  };

  const saveFromUri = async () => {
    const parsed = parseOtpauthUri(uri);
    if (!parsed) {
      Alert.alert(
        'Not a valid setup code',
        'Paste an otpauth:// link (this is what the QR code contains). Only SHA1/SHA256 with 6–8 digit codes are supported.'
      );
      return;
    }
    await save(parsed);
  };

  const saveFromManual = async () => {
    const s = secret.replace(/\s/g, '');
    if (!isValidBase32(s)) {
      Alert.alert('Invalid secret', 'The secret key must be a base32 value (letters A–Z and 2–7).');
      return;
    }
    if (!issuer.trim()) {
      Alert.alert('Missing name', 'Enter a service name (for example "Google" or "GitHub").');
      return;
    }
    await save({
      issuer: issuer.trim(),
      label: label.trim() || issuer.trim(),
      secret: s,
      algorithm: 'SHA1' as OtpAlgorithm,
      digits: 6,
      period: 30,
      type: 'totp',
    });
  };

  return (
    <>
      <Stack.Screen options={{ title: 'Add account' }} />
      <KeyboardAvoidingView
        style={{ flex: 1 }}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      >
        <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
          <Link href="/(app)/authenticator/scan" asChild>
            <Pressable style={styles.scanBtn}>
              <Text style={styles.scanBtnText}>📷  Scan QR code</Text>
            </Pressable>
          </Link>
          <Text style={styles.orDivider}>or add without the camera</Text>
          <View style={styles.tabs}>
            <Tab label="Setup key" active={mode === 'uri'} onPress={() => setMode('uri')} />
            <Tab label="Manual" active={mode === 'manual'} onPress={() => setMode('manual')} />
            <Tab label="Create" active={mode === 'create'} onPress={() => setMode('create')} />
          </View>

          {mode === 'uri' && (
            <View style={styles.card}>
              <Text style={styles.help}>
                On the service&apos;s two-factor setup screen choose &quot;Can&apos;t scan?&quot; or
                &quot;Set up manually&quot; to reveal the setup link, then paste it here.
              </Text>
              <TextInput
                style={[styles.input, styles.multiline]}
                placeholder="otpauth://totp/GitHub:you@example.com?secret=..."
                placeholderTextColor="rgba(127,127,127,0.6)"
                value={uri}
                onChangeText={setUri}
                autoCapitalize="none"
                autoCorrect={false}
                multiline
              />
              <Pressable style={styles.save} onPress={saveFromUri}>
                <Text style={styles.saveText}>Add account</Text>
              </Pressable>
            </View>
          )}

          {mode === 'manual' && (
            <View style={styles.card}>
              <Text style={styles.fieldLabel}>Service name</Text>
              <TextInput
                style={styles.input}
                placeholder="Google, GitHub, AWS…"
                placeholderTextColor="rgba(127,127,127,0.6)"
                value={issuer}
                onChangeText={setIssuer}
                autoCapitalize="words"
              />
              <Text style={styles.fieldLabel}>Account (optional)</Text>
              <TextInput
                style={styles.input}
                placeholder="you@example.com"
                placeholderTextColor="rgba(127,127,127,0.6)"
                value={label}
                onChangeText={setLabel}
                autoCapitalize="none"
                autoCorrect={false}
                keyboardType="email-address"
              />
              <Text style={styles.fieldLabel}>Secret key</Text>
              <TextInput
                style={styles.input}
                placeholder="JBSW Y3DP EHPK 3PXP"
                placeholderTextColor="rgba(127,127,127,0.6)"
                value={secret}
                onChangeText={setSecret}
                autoCapitalize="characters"
                autoCorrect={false}
              />
              <Text style={styles.hint}>
                6-digit code, 30-second refresh (the standard used by Google, GitHub, Microsoft and
                most services).
              </Text>
              <Pressable style={styles.save} onPress={saveFromManual}>
                <Text style={styles.saveText}>Add account</Text>
              </Pressable>
            </View>
          )}

          {mode === 'create' && <CreateTab onSaved={() => router.back()} />}
        </ScrollView>
      </KeyboardAvoidingView>
    </>
  );
}

/**
 * "Create in OpenIDX": mint a fresh random secret and present its QR + setup key
 * so the user can register it with a service (or a second device). Nothing is
 * stored until the user confirms — matching how a website shows a QR you commit
 * only after verifying a code.
 */
function CreateTab({ onSaved }: { onSaved: () => void }) {
  const [issuer, setIssuer] = useState('');
  const [label, setLabel] = useState('');
  const [secret, setSecret] = useState<string | null>(null);

  const generate = () => {
    if (!issuer.trim()) {
      Alert.alert('Missing name', 'Enter a name for this account first (for example a service or app name).');
      return;
    }
    // 20 bytes (160 bits) of entropy → base32, matching Google/Microsoft.
    const bytes = Crypto.getRandomBytes(20);
    setSecret(generateSecret(new Uint8Array(bytes)));
  };

  const account: Omit<OtpAccount, 'id' | 'createdAt'> | null = secret
    ? {
        issuer: issuer.trim() || 'OpenIDX',
        label: label.trim() || issuer.trim() || 'OpenIDX',
        secret,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        type: 'totp',
      }
    : null;

  const uri = account ? buildOtpauthUri(account) : '';

  const copyKey = async () => {
    if (!secret) return;
    await Clipboard.setStringAsync(secret);
    Alert.alert('Copied', 'The setup key was copied to your clipboard.');
  };

  const saveIt = async () => {
    if (!account) return;
    await addAccount(account);
    onSaved();
  };

  return (
    <View style={styles.card}>
      <Text style={styles.help}>
        OpenIDX generates a brand-new secret for you. Scan the QR (or paste the key) into the
        service or second device that should share this code, then save it here.
      </Text>
      <Text style={styles.fieldLabel}>Account name</Text>
      <TextInput
        style={styles.input}
        placeholder="My server, a service, a second phone…"
        placeholderTextColor="rgba(127,127,127,0.6)"
        value={issuer}
        onChangeText={setIssuer}
        autoCapitalize="words"
      />
      <Text style={styles.fieldLabel}>Account detail (optional)</Text>
      <TextInput
        style={styles.input}
        placeholder="you@example.com"
        placeholderTextColor="rgba(127,127,127,0.6)"
        value={label}
        onChangeText={setLabel}
        autoCapitalize="none"
        autoCorrect={false}
      />

      {!secret ? (
        <Pressable style={styles.save} onPress={generate}>
          <Text style={styles.saveText}>Generate secret & QR</Text>
        </Pressable>
      ) : (
        <>
          <View style={styles.qrBox}>
            <QRCode value={uri} size={220} />
          </View>
          <Pressable style={styles.keyCard} onPress={copyKey}>
            <Text style={styles.keyLabel}>Setup key (tap to copy)</Text>
            <Text style={styles.keyValue} selectable>
              {secret.replace(/(.{4})/g, '$1 ').trim()}
            </Text>
          </Pressable>
          <Text style={styles.hint}>
            Enter this key or scan the QR wherever the code is needed. Keep it secret.
          </Text>
          <Pressable style={styles.save} onPress={saveIt}>
            <Text style={styles.saveText}>Save to my authenticator</Text>
          </Pressable>
        </>
      )}
    </View>
  );
}

function Tab({ label, active, onPress }: { label: string; active: boolean; onPress: () => void }) {
  return (
    <Pressable style={[styles.tab, active && styles.tabActive]} onPress={onPress}>
      <Text style={[styles.tabText, active && styles.tabTextActive]}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 16 },
  scanBtn: {
    height: 52,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  scanBtnText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  orDivider: { fontSize: 12, opacity: 0.5, textAlign: 'center', marginTop: -4 },
  tabs: { flexDirection: 'row', gap: 8 },
  tab: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: 'center',
    backgroundColor: 'rgba(127,127,127,0.12)',
  },
  tabActive: { backgroundColor: '#208AEF' },
  tabText: { fontSize: 14, fontWeight: '600', opacity: 0.7 },
  tabTextActive: { color: '#fff', opacity: 1 },
  card: { gap: 10 },
  help: { fontSize: 14, opacity: 0.6, lineHeight: 20 },
  fieldLabel: { fontSize: 13, fontWeight: '600', opacity: 0.7, marginTop: 4 },
  input: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 14,
    fontSize: 16,
    backgroundColor: 'rgba(127,127,127,0.06)',
  },
  multiline: { minHeight: 96, textAlignVertical: 'top' },
  hint: { fontSize: 12, opacity: 0.5, lineHeight: 17 },
  save: {
    marginTop: 8,
    height: 52,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  saveText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  qrBox: { alignSelf: 'center', backgroundColor: '#fff', padding: 16, borderRadius: 16, marginTop: 6 },
  keyCard: { backgroundColor: 'rgba(127,127,127,0.08)', borderRadius: 14, padding: 16, gap: 6, marginTop: 6 },
  keyLabel: { fontSize: 12, fontWeight: '600', opacity: 0.55 },
  keyValue: { fontSize: 18, fontWeight: '600', letterSpacing: 1, fontVariant: ['tabular-nums'] },
});
