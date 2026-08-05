import { Tabs } from 'expo-router';
import { useQuery } from '@tanstack/react-query';
import { Text, type ColorValue } from 'react-native';

import { listPendingApprovals } from '@/features/approvals/api';
import { useTheme } from '@/hooks/use-theme';

/**
 * Bottom tab bar — the primary navigation, matching Microsoft Authenticator's
 * three-tab shell. The Authenticator (codes) tab is the default landing tab;
 * Approvals carries a live count badge; the More tab holds account, security,
 * PAM and sign-out. Detail screens (account detail, an approval, a PAM session)
 * are pushed on top from the parent Stack, so they cover the tab bar like they
 * do in the reference apps.
 */
export default function TabsLayout() {
  const theme = useTheme();

  // Live pending-approval count for the tab badge.
  const { data: pendingCount } = useQuery({
    queryKey: ['approvals'],
    queryFn: listPendingApprovals,
    refetchInterval: 30000,
    select: (r) => r.length,
  });

  return (
    <Tabs
      screenOptions={{
        headerShown: true,
        tabBarActiveTintColor: '#2563EB',
        tabBarInactiveTintColor: theme.textSecondary,
        tabBarStyle: { backgroundColor: theme.background },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Authenticator',
          tabBarLabel: 'Codes',
          tabBarIcon: ({ color }) => <TabIcon glyph="🔑" color={color} />,
        }}
      />
      <Tabs.Screen
        name="approvals"
        options={{
          title: 'Approvals',
          tabBarBadge: pendingCount && pendingCount > 0 ? pendingCount : undefined,
          tabBarIcon: ({ color }) => <TabIcon glyph="✅" color={color} />,
        }}
      />
      <Tabs.Screen
        name="more"
        options={{
          title: 'More',
          tabBarIcon: ({ color }) => <TabIcon glyph="⋯" color={color} />,
        }}
      />
    </Tabs>
  );
}

/**
 * Emoji tab glyphs keep the bar dependency-free (no icon font). The active tint
 * is applied via the surrounding label color; the glyph itself stays legible in
 * both themes.
 */
function TabIcon({ glyph, color }: { glyph: string; color: ColorValue }) {
  return <Text style={{ fontSize: 20, color }}>{glyph}</Text>;
}
