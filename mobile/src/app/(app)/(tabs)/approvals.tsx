import { useQuery } from '@tanstack/react-query';
import { Link } from 'expo-router';
import { ActivityIndicator, FlatList, StyleSheet, Text, View } from 'react-native';

import { listPendingApprovals, type AccessRequest } from '@/features/approvals/api';

/**
 * Approvals tab — the requests waiting on this user, refreshed live. Tapping a
 * card opens the approval detail (approve / deny) pushed from the parent Stack.
 */
export default function ApprovalsScreen() {
  const { data, isLoading, isError, refetch, isRefetching } = useQuery({
    queryKey: ['approvals'],
    queryFn: listPendingApprovals,
    refetchInterval: 20000,
  });

  if (isLoading) return <ActivityIndicator style={{ marginTop: 32 }} />;
  if (isError) return <Text style={styles.hint}>Couldn’t load approvals.</Text>;

  return (
    <FlatList<AccessRequest>
      data={data ?? []}
      keyExtractor={(r) => r.id}
      onRefresh={refetch}
      refreshing={isRefetching}
      contentContainerStyle={{ padding: 16 }}
      ListEmptyComponent={<Text style={styles.hint}>Nothing awaiting your approval. 🎉</Text>}
      renderItem={({ item }) => (
        <Link href={`/(app)/approvals/${item.id}`} asChild>
          <View style={styles.card}>
            <View style={styles.rowTop}>
              <Text style={styles.resource} numberOfLines={1}>
                {item.resource_name}
              </Text>
              <Text style={styles.badge}>{item.resource_type}</Text>
            </View>
            <Text style={styles.requester}>from {item.requester_name}</Text>
            {!!item.justification && (
              <Text style={styles.just} numberOfLines={2}>
                {item.justification}
              </Text>
            )}
          </View>
        </Link>
      )}
    />
  );
}

const styles = StyleSheet.create({
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  card: {
    borderRadius: 14,
    padding: 16,
    marginBottom: 12,
    backgroundColor: 'rgba(127,127,127,0.12)',
    gap: 4,
  },
  rowTop: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  resource: { fontSize: 17, fontWeight: '700', flex: 1 },
  badge: { fontSize: 11, textTransform: 'uppercase', opacity: 0.6, fontWeight: '700' },
  requester: { fontSize: 14, opacity: 0.7 },
  just: { fontSize: 14, opacity: 0.85, marginTop: 4 },
});
