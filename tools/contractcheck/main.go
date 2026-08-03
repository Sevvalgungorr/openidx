// Command contractcheck detects frontend/backend API response-shape mismatches
// of the kind that silently break the admin console (e.g. the backend returns
// {"data": [...]} while the frontend reads {policies, total}, or renames a field
// so the UI computes NaN).
//
// It works in two stages:
//
//  1. STATIC EXTRACT: scan the admin-console source for calls of the form
//     api.get<{ key1: ...; key2: ... }>('/api/v1/...') and record, per GET
//     endpoint with a plain string path, the set of top-level keys the frontend
//     expects to read off the JSON response. This is the frontend contract; it
//     has no false positives about "what the UI reads".
//
//  2. LIVE PROBE (optional, -probe): call each such GET endpoint against a
//     running deployment (default https://openidx.tdv.org) with a bearer token
//     and diff the declared keys against the actual top-level JSON keys. A
//     declared key that is absent from the real response is a real bug: the UI
//     will read undefined. Extra backend keys are reported as info only.
//
// Only GET endpoints with a static string path and an inline object-literal
// generic are checked. Endpoints typed with a named interface, a template-string
// path, or a bare/array generic are listed under "skipped" so coverage is
// visible and the tool never pretends more than it verified.
//
// Exit code is non-zero when -probe is set and any missing-key mismatch is found,
// so it can gate CI once the known set is clean.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // dev probing of self-signed edge
}

// declaredCall is one frontend api.get<{...}>('path') site.
type declaredCall struct {
	Path string
	Keys []string
	File string
	Line int
}

// matches api.get<{ ... }>('  /path  ')  with a plain single/double quoted path.
// The generic body and the path are captured; template-string paths are handled
// separately and skipped.
var reGetInlineObj = regexp.MustCompile(
	`api\.get<\{([^}]*)\}>\(\s*['"]([^'"]+)['"]`)

// matches api.get<Something>('path') or api.get<X[]>('path') or template paths —
// used only to count/report what we deliberately skip.
var reGetAnyGeneric = regexp.MustCompile(
	"api\\.get<[^>]+>\\(\\s*['\"`]")

// key names inside an inline object generic: "  foo :  Type "  ->  foo
var reObjKey = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:`)

func extractKeys(genericBody string) []string {
	// Only take top-level keys. Inline object generics here are flat
	// ({ policies: X[]; total: number }); nested objects are rare and would
	// only add keys we don't assert on. Split on ; and , at depth 0.
	var keys []string
	depth := 0
	var cur strings.Builder
	flush := func() {
		seg := strings.TrimSpace(cur.String())
		cur.Reset()
		if seg == "" {
			return
		}
		// key is the identifier before the first ':' at this level
		if m := reObjKey.FindStringSubmatch(seg); m != nil {
			keys = append(keys, m[1])
		}
	}
	for _, r := range genericBody {
		switch r {
		case '{', '<', '(', '[':
			depth++
			cur.WriteRune(r)
		case '}', '>', ')', ']':
			depth--
			cur.WriteRune(r)
		case ';', ',':
			if depth == 0 {
				flush()
			} else {
				cur.WriteRune(r)
			}
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	// de-dup, keep only the first key per segment (already the case)
	sort.Strings(keys)
	return dedup(keys)
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func lineOf(content string, idx int) int {
	return strings.Count(content[:idx], "\n") + 1
}

func main() {
	var (
		srcDir   = flag.String("src", "web/admin-console/src", "admin console source directory")
		probe    = flag.Bool("probe", false, "live-probe each GET endpoint and diff keys")
		baseURL  = flag.String("base", "https://openidx.tdv.org", "base URL for live probing")
		tokenF   = flag.String("token-file", "/tmp/admintoken.txt", "file containing a bearer token")
		insecure = flag.Bool("insecure", true, "skip TLS verification when probing")
		jsonOut  = flag.Bool("json", false, "emit findings as JSON")
	)
	flag.Parse()

	calls, skipped, err := scan(*srcDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(2)
	}

	if !*probe {
		reportStatic(calls, skipped, *jsonOut)
		return
	}

	tokenBytes, err := os.ReadFile(*tokenF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read token file %s: %v\n", *tokenF, err)
		os.Exit(2)
	}
	token := strings.TrimSpace(string(tokenBytes))

	findings := probeAll(calls, *baseURL, token, *insecure)
	os.Exit(reportProbe(calls, skipped, findings, *jsonOut))
}

func scan(srcDir string) (calls []declaredCall, skippedCount int, err error) {
	// Track how many GET generic calls we saw vs how many we could statically
	// pin to (path, keys), so skipped == total - matched.
	total := 0
	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".ts" && ext != ".tsx" {
			return nil
		}
		if strings.HasSuffix(path, ".test.ts") || strings.HasSuffix(path, ".test.tsx") {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		content := string(b)
		total += len(reGetAnyGeneric.FindAllString(content, -1))
		for _, m := range reGetInlineObj.FindAllStringSubmatchIndex(content, -1) {
			body := content[m[2]:m[3]]
			p := content[m[4]:m[5]]
			keys := extractKeys(body)
			if len(keys) == 0 {
				continue
			}
			calls = append(calls, declaredCall{
				Path: p,
				Keys: keys,
				File: path,
				Line: lineOf(content, m[0]),
			})
		}
		return nil
	})
	skippedCount = total - len(calls)
	if skippedCount < 0 {
		skippedCount = 0
	}
	return calls, skippedCount, err
}

type probeFinding struct {
	Path         string   `json:"path"`
	Status       int      `json:"status"`
	DeclaredKeys []string `json:"declared_keys"`
	ActualKeys   []string `json:"actual_keys"`
	MissingKeys  []string `json:"missing_keys"` // declared but absent in response
	Note         string   `json:"note,omitempty"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
}

func probeAll(calls []declaredCall, base, token string, insecure bool) []probeFinding {
	client := &http.Client{Timeout: 15 * time.Second}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: insecureTLS(),
		}
	}
	// De-dup by path (multiple sites may hit the same endpoint) but keep the
	// first site's file/line for reporting.
	seen := map[string]bool{}
	var findings []probeFinding
	for _, c := range calls {
		if seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		f := probeOne(client, base, token, c)
		findings = append(findings, f)
	}
	return findings
}

func probeOne(client *http.Client, base, token string, c declaredCall) probeFinding {
	f := probeFinding{Path: c.Path, DeclaredKeys: c.Keys, File: c.File, Line: c.Line}
	req, err := http.NewRequest(http.MethodGet, base+c.Path, nil)
	if err != nil {
		f.Note = "bad request: " + err.Error()
		return f
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		f.Note = "request failed: " + err.Error()
		return f
	}
	defer resp.Body.Close()
	f.Status = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		f.Note = fmt.Sprintf("non-200 (%d); cannot verify shape", resp.StatusCode)
		return f
	}
	var body interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		f.Note = "response is not JSON: " + err.Error()
		return f
	}
	obj, ok := body.(map[string]interface{})
	if !ok {
		// Frontend declared an object shape but the response is an array or
		// scalar — a genuine shape mismatch.
		f.Note = "response is not a JSON object but frontend expects an object"
		f.MissingKeys = c.Keys
		return f
	}
	actual := make([]string, 0, len(obj))
	for k := range obj {
		actual = append(actual, k)
	}
	sort.Strings(actual)
	f.ActualKeys = actual
	for _, k := range c.Keys {
		if _, present := obj[k]; !present {
			f.MissingKeys = append(f.MissingKeys, k)
		}
	}
	return f
}

func reportStatic(calls []declaredCall, skipped int, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]interface{}{"declared": calls, "skipped_generic_get_calls": skipped})
		return
	}
	fmt.Printf("Frontend GET contracts extracted: %d (static string path + inline object shape)\n", len(calls))
	fmt.Printf("Skipped GET generic calls (named type / template path / array shape): %d\n\n", skipped)
	for _, c := range calls {
		fmt.Printf("  %-55s expects {%s}\n", c.Path, strings.Join(c.Keys, ", "))
	}
	fmt.Println("\nRun with -probe to diff these against a live deployment.")
}

func reportProbe(calls []declaredCall, skipped int, findings []probeFinding, asJSON bool) int {
	var mismatches, unverified int
	for _, f := range findings {
		if len(f.MissingKeys) > 0 {
			mismatches++
		} else if f.Status != http.StatusOK {
			unverified++
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]interface{}{
			"endpoints_probed":          len(findings),
			"skipped_generic_get_calls": skipped,
			"mismatches":                mismatches,
			"unverified":                unverified,
			"findings":                  findings,
		})
		if mismatches > 0 {
			return 1
		}
		return 0
	}

	fmt.Printf("Probed %d GET endpoints (%d skipped generic calls not statically checkable)\n\n", len(findings), skipped)

	if mismatches > 0 {
		fmt.Println("MISMATCHES (frontend reads a key the backend does not return -> undefined in UI):")
		for _, f := range findings {
			if len(f.MissingKeys) == 0 {
				continue
			}
			fmt.Printf("  ✗ %s\n", f.Path)
			fmt.Printf("      missing: %s\n", strings.Join(f.MissingKeys, ", "))
			fmt.Printf("      declared: {%s}   actual: {%s}\n",
				strings.Join(f.DeclaredKeys, ", "), strings.Join(f.ActualKeys, ", "))
			if f.Note != "" {
				fmt.Printf("      note: %s\n", f.Note)
			}
			fmt.Printf("      at %s:%d\n", f.File, f.Line)
		}
		fmt.Println()
	}

	if unverified > 0 {
		fmt.Println("UNVERIFIED (non-200; needs params/data or auth to probe):")
		for _, f := range findings {
			if len(f.MissingKeys) > 0 || f.Status == http.StatusOK {
				continue
			}
			fmt.Printf("  ? %-55s %s\n", f.Path, f.Note)
		}
		fmt.Println()
	}

	ok := len(findings) - mismatches - unverified
	fmt.Printf("Summary: %d OK, %d mismatch, %d unverified\n", ok, mismatches, unverified)
	if mismatches > 0 {
		return 1
	}
	return 0
}
