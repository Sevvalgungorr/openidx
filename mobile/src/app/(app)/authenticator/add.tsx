import { Link, Stack, useRouter } from 'expo-router';
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

import { isValidBase32 } from '@/features/authenticator/crypto';
import {
  generateTOTP,
  parseOtpauthUri,
  type OtpAccount,
  type OtpAlgorithm,
} from '@/features/authenticator/otp';
import { addAccount } from '@/features/authenticator/store';

type Mode = 'uri' | 'manual';

/**
 * Add-account screen. Two paths, mirroring Google Authenticator:
 *  - "Scan / paste setup key": paste an otpauth:// URI (the exact string a QR
 *    code encodes) and every field is filled in automatically.
 *  - "Enter manually": type the issuer, account and secret from the service's
 *    "can't scan?" screen.
 *
 * The secret is validated by actually generating a code before saving, so a
 * mistyped key is caught immediately rather than silently producing wrong codes.
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
      // Prove the secret produces a code before persisting it.
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
            <Tab label="Setup key / link" active={mode === 'uri'} onPress={() => setMode('uri')} />
            <Tab label="Enter manually" active={mode === 'manual'} onPress={() => setMode('manual')} />
          </View>

          {mode === 'uri' ? (
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
          ) : (
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
        </ScrollView>
      </KeyboardAvoidingView>
    </>
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
});
