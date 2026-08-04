import { Stack } from 'expo-router';
import { useState } from 'react';
import {
  ActivityIndicator,
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

import { exportBackup, importBackup } from '@/features/authenticator/backup';

/**
 * Encrypted backup / restore of the authenticator accounts. The backup is a
 * passphrase-protected blob (encrypt-then-MAC over HMAC-SHA256); losing the
 * passphrase means losing the backup — there is no recovery, by design.
 *
 * To avoid adding a native file/clipboard dependency, export shows the blob in a
 * selectable field to copy out (into a password manager / secure note / file),
 * and restore takes the pasted blob. A future build can wire expo-clipboard /
 * expo-sharing for one-tap copy/save.
 */
export default function BackupScreen() {
  const [mode, setMode] = useState<'menu' | 'export' | 'import'>('menu');

  return (
    <>
      <Stack.Screen options={{ title: 'Backup & restore' }} />
      <KeyboardAvoidingView
        style={styles.fill}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <ScrollView contentContainerStyle={styles.container}>
          {mode === 'menu' && (
            <>
              <Text style={styles.blurb}>
                Create an encrypted backup of your authenticator accounts so you can
                restore them on a new phone. The backup is protected by a passphrase
                you choose — keep it somewhere safe; it cannot be recovered.
              </Text>
              <Pressable style={styles.primary} onPress={() => setMode('export')}>
                <Text style={styles.primaryText}>Create encrypted backup</Text>
              </Pressable>
              <Pressable style={styles.secondary} onPress={() => setMode('import')}>
                <Text style={styles.secondaryText}>Restore from backup</Text>
              </Pressable>
            </>
          )}
          {mode === 'export' && <ExportPanel onDone={() => setMode('menu')} />}
          {mode === 'import' && <ImportPanel onDone={() => setMode('menu')} />}
        </ScrollView>
      </KeyboardAvoidingView>
    </>
  );
}

function ExportPanel({ onDone }: { onDone: () => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [blob, setBlob] = useState<string | null>(null);

  const create = async () => {
    if (passphrase.length < 8) {
      Alert.alert('Weak passphrase', 'Use at least 8 characters.');
      return;
    }
    if (passphrase !== confirm) {
      Alert.alert('Passphrases do not match');
      return;
    }
    try {
      setBusy(true);
      const out = await exportBackup(passphrase);
      setBlob(out);
    } catch (e) {
      Alert.alert('Backup failed', e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (blob) {
    return (
      <View style={styles.panel}>
        <Text style={styles.h}>Your encrypted backup</Text>
        <Text style={styles.blurb}>
          Copy this text and store it safely (a password manager, secure note, or
          file). You will need it and your passphrase to restore.
        </Text>
        <TextInput
          style={styles.blob}
          value={blob}
          multiline
          editable={false}
          selectTextOnFocus
        />
        <Pressable style={styles.primary} onPress={onDone}>
          <Text style={styles.primaryText}>Done</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.panel}>
      <Text style={styles.h}>Choose a backup passphrase</Text>
      <TextInput
        style={styles.input}
        placeholder="Passphrase (min 8 chars)"
        secureTextEntry
        autoCapitalize="none"
        value={passphrase}
        onChangeText={setPassphrase}
      />
      <TextInput
        style={styles.input}
        placeholder="Confirm passphrase"
        secureTextEntry
        autoCapitalize="none"
        value={confirm}
        onChangeText={setConfirm}
      />
      <Pressable style={styles.primary} disabled={busy} onPress={create}>
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.primaryText}>Create backup</Text>
        )}
      </Pressable>
      <Pressable style={styles.link} onPress={onDone}>
        <Text style={styles.linkText}>Cancel</Text>
      </Pressable>
    </View>
  );
}

function ImportPanel({ onDone }: { onDone: () => void }) {
  const [blob, setBlob] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);

  const restore = async () => {
    if (!blob.trim()) {
      Alert.alert('Paste your backup', 'Paste the encrypted backup text first.');
      return;
    }
    try {
      setBusy(true);
      const n = await importBackup(blob.trim(), passphrase);
      Alert.alert('Restored', `${n} account${n === 1 ? '' : 's'} imported.`, [
        { text: 'OK', onPress: onDone },
      ]);
    } catch (e) {
      Alert.alert('Restore failed', e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <View style={styles.panel}>
      <Text style={styles.h}>Restore from backup</Text>
      <Text style={styles.blurb}>
        Paste the encrypted backup text and enter the passphrase you used to
        create it. Restored accounts are added to this device.
      </Text>
      <TextInput
        style={styles.blob}
        placeholder="Paste backup text here"
        multiline
        autoCapitalize="none"
        value={blob}
        onChangeText={setBlob}
      />
      <TextInput
        style={styles.input}
        placeholder="Passphrase"
        secureTextEntry
        autoCapitalize="none"
        value={passphrase}
        onChangeText={setPassphrase}
      />
      <Pressable style={styles.primary} disabled={busy} onPress={restore}>
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.primaryText}>Restore</Text>
        )}
      </Pressable>
      <Pressable style={styles.link} onPress={onDone}>
        <Text style={styles.linkText}>Cancel</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  container: { padding: 20, gap: 14 },
  blurb: { fontSize: 15, opacity: 0.7, lineHeight: 21 },
  panel: { gap: 12 },
  h: { fontSize: 18, fontWeight: '700' },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 14,
    fontSize: 16,
  },
  blob: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 14,
    fontSize: 12,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    minHeight: 140,
    textAlignVertical: 'top',
  },
  primary: {
    backgroundColor: '#208AEF',
    borderRadius: 12,
    height: 52,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryText: { color: '#fff', fontSize: 17, fontWeight: '700' },
  secondary: {
    borderWidth: 1,
    borderColor: '#208AEF',
    borderRadius: 12,
    height: 52,
    alignItems: 'center',
    justifyContent: 'center',
  },
  secondaryText: { color: '#208AEF', fontSize: 17, fontWeight: '700' },
  link: { alignItems: 'center', paddingVertical: 10 },
  linkText: { color: '#208AEF', fontSize: 15, fontWeight: '600' },
});
