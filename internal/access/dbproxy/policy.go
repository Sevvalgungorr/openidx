package dbproxy

import (
	"fmt"
	"strings"
)

// StatementPolicy constrains what SQL a brokered session may run. It is
// enforced at the proxy's Query/Parse decode point — server-side, before the
// statement reaches the upstream database — so it cannot be bypassed by a
// different client the way UI-level checks can. A nil policy allows
// everything (audit-only, today's behavior).
//
// Classification is deliberately lexical, not a SQL parse: the scanner
// understands PostgreSQL quoting (single-quote doubling, double-quoted
// identifiers, $tag$ dollar quoting), line and nested block comments, and
// statement boundaries well enough to find the top-level statement class. Anything it cannot positively classify as read-only is
// treated as a write — the policy FAILS CLOSED, so a scanner limitation can
// over-block but never under-block.
type StatementPolicy struct {
	// ReadOnly permits only statements that cannot modify data or schema:
	// SELECT/SHOW/VALUES/TABLE/FETCH plus transaction and session control
	// (BEGIN/COMMIT/ROLLBACK/SET/...). WITH is resolved to its top-level
	// statement (a CTE wrapping INSERT is a write), EXPLAIN to the statement
	// it explains (EXPLAIN ANALYZE executes it), and COPY by direction
	// (TO = export/read, FROM = import/write).
	ReadOnly bool
	// Deny rejects statement classes outright, before the ReadOnly check and
	// regardless of it — e.g. ["DROP", "TRUNCATE", "ALTER"]. Matching is
	// case-insensitive on the resolved class.
	Deny []string
}

// Check returns nil when every statement in sql (a simple-protocol Query may
// carry several, separated by top-level semicolons) is allowed. The returned
// error is safe to surface to the client.
func (p *StatementPolicy) Check(sql string) error {
	if p == nil {
		return nil
	}
	deny := make(map[string]bool, len(p.Deny))
	for _, d := range p.Deny {
		deny[strings.ToUpper(strings.TrimSpace(d))] = true
	}
	for _, stmt := range splitStatements(sql) {
		class, readOnly := classifyStatement(stmt)
		if class == "" {
			continue // empty statement (bare semicolon, comment-only)
		}
		if deny[class] {
			return fmt.Errorf("policy denies %s statements on this session", class)
		}
		if p.ReadOnly && !readOnly {
			return fmt.Errorf("read-only session: %s is not allowed", class)
		}
	}
	return nil
}

// readOnlyClasses are statement classes that cannot modify data or schema.
// Transaction/session control is included so drivers and psql work normally
// (a write attempted inside BEGIN is still classified per-statement).
// PREPARE/EXECUTE and DO are intentionally absent: their effect depends on a
// body this scanner does not evaluate, so they fail closed.
var readOnlyClasses = map[string]bool{
	"SELECT": true, "SHOW": true, "VALUES": true, "TABLE": true,
	"FETCH": true, "MOVE": true, "CLOSE": true, "DECLARE": false,
	"SET": true, "RESET": true, "BEGIN": true, "START": true,
	"COMMIT": true, "END": true, "ROLLBACK": true, "ABORT": true,
	"SAVEPOINT": true, "RELEASE": true, "DEALLOCATE": true, "DISCARD": true,
}

// classifyStatement resolves a single statement to its class keyword and
// whether that class is read-only. WITH and EXPLAIN are resolved through to
// the statement they wrap; COPY is resolved by direction.
func classifyStatement(stmt string) (class string, readOnly bool) {
	sc := newSQLScanner(stmt)
	for {
		tok, ok := sc.nextKeyword(0)
		if !ok {
			return "", false
		}
		switch tok {
		case "EXPLAIN":
			// Skip an option list — "EXPLAIN (ANALYZE, COSTS OFF)" — or the
			// legacy ANALYZE/VERBOSE words, then classify the wrapped
			// statement: EXPLAIN ANALYZE executes what it explains.
			sc.skipParenGroup()
			for {
				next, nok := sc.peekKeyword(0)
				if !nok || (next != "ANALYZE" && next != "VERBOSE") {
					break
				}
				sc.nextKeyword(0)
			}
			continue // classify the remainder
		case "WITH":
			// PostgreSQL allows data-modifying CTEs — WITH t AS (DELETE ...)
			// SELECT ... — so a depth-0 scan for the main statement is not
			// enough. Scan the ENTIRE remainder at every depth: any
			// INSERT/UPDATE/DELETE/MERGE keyword makes the statement a write;
			// only then does the first depth-0 SELECT/TABLE/VALUES make it a
			// read. (An unquoted identifier that collides with one of these
			// keywords over-blocks — fail closed; quoting it un-blocks.)
			mainClass := ""
			for {
				kind, _ := sc.next()
				if kind == tokEOF {
					break
				}
				if kind != tokWord {
					continue
				}
				switch sc.word {
				case "INSERT", "UPDATE", "DELETE", "MERGE":
					return sc.word, false
				case "SELECT", "TABLE", "VALUES":
					if sc.depth == 0 && mainClass == "" {
						mainClass = sc.word
					}
				}
			}
			if mainClass != "" {
				return mainClass, true
			}
			return "WITH", false // malformed: fail closed
		case "COPY":
			// COPY ... TO exports (read); COPY ... FROM imports (write).
			for {
				next, nok := sc.nextKeyword(0)
				if !nok {
					return "COPY", false
				}
				if next == "TO" {
					return "COPY", true
				}
				if next == "FROM" {
					return "COPY", false
				}
			}
		default:
			return tok, readOnlyClasses[tok]
		}
	}
}

// splitStatements splits sql on top-level semicolons, honoring quoting and
// comments. Returned fragments may be empty or comment-only.
func splitStatements(sql string) []string {
	sc := newSQLScanner(sql)
	var out []string
	start := 0
	for {
		kind, pos := sc.next()
		switch kind {
		case tokEOF:
			out = append(out, sql[start:])
			return out
		case tokPunct:
			if sql[pos] == ';' && sc.depth == 0 {
				out = append(out, sql[start:pos])
				start = pos + 1
			}
		}
	}
}

// --- lexical scanner -------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokWord
	tokQuoted // quoted identifier or string literal — never a keyword
	tokPunct
)

// sqlScanner walks SQL text token by token, skipping whitespace and comments,
// treating quoted regions as single tokens, and tracking parenthesis depth.
type sqlScanner struct {
	s     string
	i     int
	depth int
	word  string // last tokWord, uppercased
}

func newSQLScanner(s string) *sqlScanner { return &sqlScanner{s: s} }

// next advances one token; for tokWord the uppercased text is in sc.word.
// pos is the byte offset the token starts at.
func (sc *sqlScanner) next() (kind tokKind, pos int) {
	s, n := sc.s, len(sc.s)
	for sc.i < n {
		c := s[sc.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			sc.i++
		case c == '-' && sc.i+1 < n && s[sc.i+1] == '-':
			// line comment
			for sc.i < n && s[sc.i] != '\n' {
				sc.i++
			}
		case c == '/' && sc.i+1 < n && s[sc.i+1] == '*':
			// block comment; PostgreSQL block comments nest
			depth := 1
			sc.i += 2
			for sc.i < n && depth > 0 {
				if s[sc.i] == '/' && sc.i+1 < n && s[sc.i+1] == '*' {
					depth++
					sc.i += 2
				} else if s[sc.i] == '*' && sc.i+1 < n && s[sc.i+1] == '/' {
					depth--
					sc.i += 2
				} else {
					sc.i++
				}
			}
		case c == '\'' || c == '"':
			// String literal / quoted identifier. Doubling ('' or "") escapes
			// the quote in both modes. Backslash escapes are deliberately NOT
			// honored: with standard_conforming_strings=on the server treats
			// backslash literally, and honoring it here could make the scanner
			// swallow a real statement boundary (an under-block). Ignoring it
			// can only end a string early and over-block — fail closed.
			start := sc.i
			q := c
			sc.i++
			for sc.i < n {
				if s[sc.i] == q {
					if sc.i+1 < n && s[sc.i+1] == q {
						sc.i += 2
						continue
					}
					sc.i++
					break
				}
				sc.i++
			}
			return tokQuoted, start
		case c == '$':
			// Dollar quote $tag$...$tag$ (tag = letters/underscore/digits, not
			// starting with a digit). A '$' followed by a digit is a positional
			// parameter, not a quote.
			if tagEnd, ok := sc.dollarTag(sc.i); ok {
				start := sc.i
				tag := s[sc.i : tagEnd+1]
				sc.i = tagEnd + 1
				if end := strings.Index(s[sc.i:], tag); end >= 0 {
					sc.i += end + len(tag)
				} else {
					sc.i = n // unterminated: consume the rest (fail closed)
				}
				return tokQuoted, start
			}
			sc.i++
			return tokPunct, sc.i - 1
		case isWordStart(c):
			start := sc.i
			for sc.i < n && isWordChar(s[sc.i]) {
				sc.i++
			}
			sc.word = strings.ToUpper(s[start:sc.i])
			return tokWord, start
		default:
			if c == '(' {
				sc.depth++
			} else if c == ')' && sc.depth > 0 {
				sc.depth--
			}
			sc.i++
			return tokPunct, sc.i - 1
		}
	}
	return tokEOF, n
}

// dollarTag reports whether a dollar-quote tag starts at i, returning the
// index of the closing '$' of the opening tag. Tags are letters, digits and
// underscores (no leading digit — '$1' is a positional parameter).
func (sc *sqlScanner) dollarTag(i int) (int, bool) {
	s, n := sc.s, len(sc.s)
	j := i + 1
	for j < n {
		c := s[j]
		isTagChar := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isTagChar {
			break
		}
		if j == i+1 && c >= '0' && c <= '9' {
			return 0, false // $1, $2... — parameter, not a quote
		}
		j++
	}
	if j < n && s[j] == '$' {
		return j, true
	}
	return 0, false
}

// nextKeyword advances to the next word token at exactly the given paren
// depth and returns it uppercased.
func (sc *sqlScanner) nextKeyword(depth int) (string, bool) {
	for {
		kind, _ := sc.next()
		if kind == tokEOF {
			return "", false
		}
		if kind == tokWord && sc.depth == depth {
			return sc.word, true
		}
	}
}

// peekKeyword returns the next depth-matched keyword without consuming it.
func (sc *sqlScanner) peekKeyword(depth int) (string, bool) {
	saved := *sc
	w, ok := sc.nextKeyword(depth)
	*sc = saved
	return w, ok
}

// skipParenGroup consumes a parenthesized group if one is next.
func (sc *sqlScanner) skipParenGroup() {
	saved := *sc
	kind, pos := sc.next()
	if kind != tokPunct || pos >= len(sc.s) || sc.s[pos] != '(' {
		*sc = saved
		return
	}
	for sc.depth > 0 {
		if k, _ := sc.next(); k == tokEOF {
			return
		}
	}
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isWordChar(c byte) bool {
	return isWordStart(c) || (c >= '0' && c <= '9') || c == '$'
}
