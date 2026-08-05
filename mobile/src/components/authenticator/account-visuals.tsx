import Svg, { Circle } from 'react-native-svg';
import { StyleSheet, Text, View } from 'react-native';

import { tileColor, tileInitials } from '@/features/authenticator/branding';

/**
 * The colored, rounded issuer tile with initials — the leading avatar on every
 * account row, exactly like Microsoft Authenticator.
 */
export function IssuerAvatar({ issuer, size = 44 }: { issuer: string; size?: number }) {
  return (
    <View
      style={[
        styles.avatar,
        {
          width: size,
          height: size,
          borderRadius: size * 0.28,
          backgroundColor: tileColor(issuer),
        },
      ]}
    >
      <Text style={[styles.avatarText, { fontSize: size * 0.36 }]}>{tileInitials(issuer)}</Text>
    </View>
  );
}

/**
 * A circular countdown ring around the seconds-remaining number, the way the
 * newer authenticator apps show TOTP expiry. Turns red in the final seconds.
 */
export function CountdownRing({
  remaining,
  period,
  size = 34,
  stroke = 3,
}: {
  remaining: number;
  period: number;
  size?: number;
  stroke?: number;
}) {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const fraction = Math.max(0, Math.min(1, remaining / period));
  const dashOffset = circumference * (1 - fraction);
  const urgent = remaining <= 5;
  const color = urgent ? '#DC2626' : '#2563EB';

  return (
    <View style={{ width: size, height: size, alignItems: 'center', justifyContent: 'center' }}>
      <Svg width={size} height={size} style={StyleSheet.absoluteFill}>
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(127,127,127,0.2)"
          strokeWidth={stroke}
          fill="none"
        />
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          // Start the ring at 12 o'clock and drain clockwise.
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </Svg>
      <Text style={[styles.ringText, { color }]}>{remaining}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  avatar: { alignItems: 'center', justifyContent: 'center' },
  avatarText: { color: '#fff', fontWeight: '700' },
  ringText: { fontSize: 12, fontWeight: '700', fontVariant: ['tabular-nums'] },
});
