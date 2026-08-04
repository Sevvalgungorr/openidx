import { Stack, useRouter } from 'expo-router';
import { useRef, useState } from 'react';
import { Alert, Pressable, StyleSheet, Text, View } from 'react-native';

import { parseOtpauthUri } from '@/features/authenticator/otp';
import { addAccount } from '@/features/authenticator/store';
import { parsePushEnrollQR, completeQrEnrollment } from '@/features/mfa/push';

/**
 * Camera QR scanning for authenticator enrollment — point the phone at the
 * QR code a service shows during 2FA setup, exactly like Google Authenticator.
 *
 * expo-camera is a NATIVE module: it exists in dev-client / EAS builds (the
 * app.json plugin adds the camera permission strings) but not in a JS-only
 * bundle. It is loaded optionally — same pattern as the OidxZiti module — so
 * the app still builds and runs everywhere; without it this screen degrades
 * to a hint pointing at the paste/manual flows, which always work.
 */
type CameraModule = typeof import('expo-camera');

let Camera: CameraModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  Camera = require('expo-camera') as CameraModule;
  // Probe: the JS package can be present while the native side is not (JS-only
  // bundle). CameraView is undefined in that case.
  if (!Camera?.CameraView) Camera = null;
} catch {
  Camera = null;
}

export default function ScanScreen() {
  return (
    <>
      <Stack.Screen options={{ title: 'Scan QR code' }} />
      {Camera ? <Scanner camera={Camera} /> : <Unavailable />}
    </>
  );
}

function Scanner({ camera }: { camera: CameraModule }) {
  const router = useRouter();
  const { CameraView, useCameraPermissions } = camera;
  const [permission, requestPermission] = useCameraPermissions();
  // Bad QR codes fire onBarcodeScanned continuously; gate the alert so the
  // user isn't buried, and stop processing entirely once one code is accepted.
  const busy = useRef(false);
  const [rejected, setRejected] = useState(false);

  if (!permission) {
    return <Centered title="Preparing camera…" />;
  }
  if (!permission.granted) {
    return (
      <Centered
        title="Camera access needed"
        body="OpenIDX needs the camera to scan the QR code a service shows during two-factor setup."
      >
        <Pressable style={styles.cta} onPress={requestPermission}>
          <Text style={styles.ctaText}>Allow camera</Text>
        </Pressable>
      </Centered>
    );
  }

  const onScanned = async ({ data }: { data: string }) => {
    if (busy.current) return;

    // First: is this an OpenIDX push-authenticator enrollment QR (from the
    // admin console's "Enroll via Authenticator App")? If so, bind this device
    // as a push authenticator instead of adding a TOTP account.
    const enroll = parsePushEnrollQR(data);
    if (enroll) {
      busy.current = true;
      try {
        await completeQrEnrollment(enroll);
        Alert.alert(
          'Device enrolled',
          `This phone is now a push authenticator for ${enroll.account}.`,
          [{ text: 'OK', onPress: () => router.replace('/(app)/authenticator') }]
        );
      } catch (e) {
        busy.current = false;
        Alert.alert('Enrollment failed', e instanceof Error ? e.message : String(e));
      }
      return;
    }

    const parsed = parseOtpauthUri(data);
    if (!parsed) {
      if (!rejected) {
        setRejected(true);
        Alert.alert(
          'Not an authenticator code',
          'This QR code is not an otpauth:// setup code. Point the camera at the QR shown on the service’s two-factor setup screen.',
          [{ text: 'OK', onPress: () => setRejected(false) }]
        );
      }
      return;
    }
    busy.current = true;
    try {
      await addAccount(parsed);
      router.replace('/(app)/authenticator');
    } catch (e) {
      busy.current = false;
      Alert.alert('Could not save', e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <View style={styles.fill}>
      <CameraView
        style={styles.fill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={onScanned}
      />
      <View style={styles.overlay} pointerEvents="none">
        <View style={styles.frame} />
        <Text style={styles.overlayText}>Point at the 2FA setup QR code</Text>
      </View>
    </View>
  );
}

function Unavailable() {
  const router = useRouter();
  return (
    <Centered
      title="Camera not available in this build"
      body={
        'QR scanning needs the camera native module, which is included in development and EAS builds of the app. ' +
        'You can still add the account by pasting the setup link or entering the secret key manually.'
      }
    >
      <Pressable style={styles.cta} onPress={() => router.replace('/(app)/authenticator/add')}>
        <Text style={styles.ctaText}>Enter code instead</Text>
      </Pressable>
    </Centered>
  );
}

function Centered({
  title,
  body,
  children,
}: {
  title: string;
  body?: string;
  children?: React.ReactNode;
}) {
  return (
    <View style={styles.centered}>
      <Text style={styles.title}>{title}</Text>
      {!!body && <Text style={styles.body}>{body}</Text>}
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  centered: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 32, gap: 14 },
  title: { fontSize: 20, fontWeight: '700', textAlign: 'center' },
  body: { fontSize: 15, opacity: 0.6, textAlign: 'center', lineHeight: 21 },
  cta: {
    marginTop: 8,
    height: 50,
    paddingHorizontal: 28,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  ctaText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  overlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 18,
  },
  frame: {
    width: 230,
    height: 230,
    borderRadius: 24,
    borderWidth: 3,
    borderColor: 'rgba(255,255,255,0.85)',
  },
  overlayText: {
    color: '#fff',
    fontSize: 15,
    fontWeight: '600',
    textShadowColor: 'rgba(0,0,0,0.6)',
    textShadowRadius: 6,
  },
});
