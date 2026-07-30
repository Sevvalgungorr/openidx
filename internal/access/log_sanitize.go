package access

import "strings"

// scrubLogValue strips CR/LF from a value before it is placed in a log field,
// so a caller-supplied identifier (a URL path param, a JWT subject, an agent
// id) can't forge extra log lines. Defense in depth on top of zap's JSON
// encoder, and it clears CodeQL's log-injection sink. Mirrors the helper of
// the same name in internal/identity and internal/provisioning.
//
// Uses chained strings.ReplaceAll (not strings.NewReplacer) deliberately:
// ReplaceAll on "\n"/"\r" is the sanitizer shape CodeQL's go/log-injection
// query recognizes, so flows through this helper are provably cut.
func scrubLogValue(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
}
