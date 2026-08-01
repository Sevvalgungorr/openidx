package dbproxy

import (
	"strings"
	"testing"
)

func TestStatementPolicyReadOnly(t *testing.T) {
	pol := &StatementPolicy{ReadOnly: true}

	allowed := []string{
		"SELECT * FROM users",
		"select 1",
		"  \n\t SELECT 1",
		"-- comment\nSELECT 1",
		"/* block /* nested */ still comment */ SELECT 1",
		"SHOW server_version",
		"TABLE users",
		"VALUES (1), (2)",
		"BEGIN", "COMMIT", "ROLLBACK", "ABORT",
		"START TRANSACTION READ ONLY",
		"SET search_path TO public",
		"RESET all",
		"SAVEPOINT sp1", "RELEASE SAVEPOINT sp1",
		"FETCH 10 FROM cur", "CLOSE cur", "MOVE 5 IN cur",
		"DEALLOCATE stmt", "DISCARD ALL",
		"WITH t AS (SELECT 1) SELECT * FROM t",
		"WITH RECURSIVE t(n) AS (VALUES (1) UNION ALL SELECT n+1 FROM t WHERE n < 5) SELECT * FROM t",
		"EXPLAIN SELECT 1",
		"EXPLAIN ANALYZE SELECT 1",
		"EXPLAIN (ANALYZE, COSTS OFF) SELECT 1",
		"COPY users TO STDOUT",
		"COPY (SELECT * FROM users) TO STDOUT",
		"SELECT 1; SELECT 2;",
		"SELECT ';INSERT INTO x VALUES (1)'", // statement text inside a string
		"SELECT $tag$; DROP TABLE x; $tag$",  // ... and inside a dollar quote
		`SELECT ";DELETE FROM x" FROM t`,     // ... and inside a quoted identifier
		"; ;  -- empty statements\n;",
	}
	for _, sql := range allowed {
		if err := pol.Check(sql); err != nil {
			t.Errorf("read-only should allow %q, got %v", sql, err)
		}
	}

	blocked := []string{
		"INSERT INTO users VALUES (1)",
		"insert into users values (1)",
		"UPDATE users SET name = 'x'",
		"DELETE FROM users",
		"MERGE INTO users u USING v ON u.id = v.id WHEN MATCHED THEN DELETE",
		"TRUNCATE users",
		"DROP TABLE users",
		"CREATE TABLE t (id int)",
		"ALTER TABLE users ADD COLUMN x int",
		"GRANT ALL ON users TO public",
		"SELECT 1; DELETE FROM users", // write hidden behind a read
		"/* SELECT */ DELETE FROM users",
		"WITH t AS (SELECT 1) INSERT INTO users SELECT * FROM t", // CTE wrapping a write
		"WITH t AS (DELETE FROM users RETURNING *) SELECT * FROM t",
		"EXPLAIN ANALYZE INSERT INTO users VALUES (1)", // EXPLAIN ANALYZE executes
		"EXPLAIN (ANALYZE) DELETE FROM users",
		"COPY users FROM STDIN",
		"DO $$ BEGIN DELETE FROM users; END $$", // body not evaluated: fail closed
		"PREPARE s AS INSERT INTO users VALUES (1)",
		"EXECUTE s",
		"VACUUM users",
		"REFRESH MATERIALIZED VIEW mv",
		"CALL do_things()",
	}
	for _, sql := range blocked {
		if err := pol.Check(sql); err == nil {
			t.Errorf("read-only should block %q", sql)
		}
	}
}

func TestStatementPolicyDeny(t *testing.T) {
	pol := &StatementPolicy{Deny: []string{"drop", "TRUNCATE"}}

	if err := pol.Check("DROP TABLE users"); err == nil || !strings.Contains(err.Error(), "DROP") {
		t.Errorf("deny list should block DROP, got %v", err)
	}
	if err := pol.Check("truncate users"); err == nil {
		t.Error("deny list should block TRUNCATE case-insensitively")
	}
	if err := pol.Check("SELECT 1; DROP TABLE users"); err == nil {
		t.Error("deny list should block DROP in a multi-statement query")
	}
	// Writes are fine when only a deny list is set (no ReadOnly).
	if err := pol.Check("INSERT INTO users VALUES (1)"); err != nil {
		t.Errorf("INSERT should pass a DROP/TRUNCATE deny list, got %v", err)
	}
	// DROP mentioned in a string is not a DROP statement.
	if err := pol.Check("SELECT 'DROP TABLE users'"); err != nil {
		t.Errorf("string containing DROP should pass, got %v", err)
	}
}

func TestStatementPolicyNil(t *testing.T) {
	var pol *StatementPolicy
	if err := pol.Check("DROP TABLE users"); err != nil {
		t.Errorf("nil policy must allow everything, got %v", err)
	}
}

func TestClassifyStatement(t *testing.T) {
	cases := []struct {
		sql      string
		class    string
		readOnly bool
	}{
		{"SELECT 1", "SELECT", true},
		{"WITH t AS (SELECT 1) SELECT * FROM t", "SELECT", true},
		{"WITH t AS (SELECT 1) INSERT INTO x SELECT * FROM t", "INSERT", false},
		{"EXPLAIN (ANALYZE, BUFFERS) UPDATE x SET a=1", "UPDATE", false},
		{"EXPLAIN VERBOSE SELECT 1", "SELECT", true},
		{"COPY x TO STDOUT", "COPY", true},
		{"COPY x FROM '/tmp/f'", "COPY", false},
		{"", "", false},
		{"-- just a comment", "", false},
		{"CREATE INDEX idx ON t (a)", "CREATE", false},
	}
	for _, c := range cases {
		class, ro := classifyStatement(c.sql)
		if class != c.class || ro != c.readOnly {
			t.Errorf("classify(%q) = (%q, %v), want (%q, %v)", c.sql, class, ro, c.class, c.readOnly)
		}
	}
}

func TestSplitStatements(t *testing.T) {
	got := splitStatements("SELECT 1; SELECT ';'; SELECT $x$;$x$")
	if len(got) != 3 {
		t.Fatalf("expected 3 statements, got %d: %q", len(got), got)
	}
	if strings.TrimSpace(got[1]) != "SELECT ';'" {
		t.Errorf("semicolon inside string split wrongly: %q", got[1])
	}
	if strings.TrimSpace(got[2]) != "SELECT $x$;$x$" {
		t.Errorf("semicolon inside dollar quote split wrongly: %q", got[2])
	}
}
