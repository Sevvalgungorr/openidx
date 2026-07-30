package access

import (
	"strings"
	"testing"
)

// The privilege-graph reachSQL must be a recursive CTE (it walks composite_roles
// transitively) and must normalize principal_id types (uuid in vault, varchar in
// pam) so the same query works for both grant tables.
func TestReachSQLShape(t *testing.T) {
	for _, tc := range []struct{ table, col string }{
		{"vault_access_grants", "secret_id"},
		{"pam_entry_grants", "entry_id"},
	} {
		q := reachSQL(tc.table, tc.col)
		if !strings.Contains(q, "WITH RECURSIVE") {
			t.Fatalf("%s: reachSQL must use WITH RECURSIVE (walks composite_roles)", tc.table)
		}
		if !strings.Contains(q, "composite_roles") {
			t.Fatalf("%s: reachSQL must expand roles transitively via composite_roles", tc.table)
		}
		if !strings.Contains(q, "principal_id::text") {
			t.Fatalf("%s: reachSQL must normalize principal_id to text (uuid vs varchar)", tc.table)
		}
		if !strings.Contains(q, tc.table) || !strings.Contains(q, tc.col) {
			t.Fatalf("%s/%s: reachSQL must reference the grant table + resource column", tc.table, tc.col)
		}
		// Only expired-excluding grants are counted.
		if !strings.Contains(q, "expires_at IS NULL OR expires_at > NOW()") {
			t.Fatalf("%s: reachSQL must exclude expired grants", tc.table)
		}
	}
}
