// Package directory — LDAP/Active Directory connection diagnostics (auto-detect
// and suggest fixes for the common misconfigurations that silently break sync).
//
// Configuring an on-prem AD/LDAP sync is error-prone: the wrong port for TLS,
// an OpenLDAP user filter pointed at Active Directory (which returns zero
// users), an email attribute that is empty on every AD object, a missing
// base DN, etc. Each of these produces either a confusing error or — worse — a
// "successful" sync that imports nothing.
//
// Diagnose runs a staged series of LIVE probes against the directory server and
// returns actionable findings: what is wrong, why it matters, and a concrete
// suggested value the UI can offer as a one-click fix. It is safe (read-only,
// bounded result sizes) and fast (each probe is time-boxed).
//
// The staged approach means every probe builds on the last: reachability →
// TLS/port → bind → base DN → user filter → attribute mapping → groups. A probe
// that can't run because an earlier stage failed is reported as "skipped" with
// the blocking reason, so the operator always sees the first real problem.
package directory

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Severity ranks a finding.
type Severity string

const (
	SeverityError Severity = "error" // sync will not work until fixed
	SeverityWarn  Severity = "warning"
	SeverityInfo  Severity = "info"
	SeverityOK    Severity = "ok"
)

// Finding is one diagnostic result. Suggested holds config keys the UI can
// apply directly (same JSON keys as the stored LDAP config).
type Finding struct {
	Stage     string         `json:"stage"`
	Severity  Severity       `json:"severity"`
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	Suggested map[string]any `json:"suggested,omitempty"` // config patch to apply
	Evidence  map[string]any `json:"evidence,omitempty"`  // counts/samples backing the finding
}

// DiagnoseResult is the full report.
type DiagnoseResult struct {
	OK       bool      `json:"ok"` // true when no error-severity findings remain
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings"`
	// SuggestedConfig is the merged one-click patch across all findings — the UI
	// can offer "apply all suggestions".
	SuggestedConfig map[string]any `json:"suggested_config,omitempty"`
}

// probeTimeout bounds each network probe.
const probeTimeout = 8 * time.Second

// Diagnose runs the full staged diagnosis against the supplied LDAP config and
// returns a report with suggested fixes. It never mutates cfg.
func Diagnose(ctx context.Context, cfg LDAPConfig) *DiagnoseResult {
	res := &DiagnoseResult{SuggestedConfig: map[string]any{}}
	add := func(f Finding) {
		res.Findings = append(res.Findings, f)
		for k, v := range f.Suggested {
			res.SuggestedConfig[k] = v
		}
	}

	host := strings.TrimSpace(cfg.Host)
	if host != cfg.Host {
		add(Finding{Stage: "input", Severity: SeverityWarn,
			Title:     "Host has surrounding whitespace",
			Detail:    "The host value contains leading/trailing spaces, which can cause connection failures.",
			Suggested: map[string]any{"host": host}})
	}
	if host == "" {
		add(Finding{Stage: "input", Severity: SeverityError,
			Title: "Host is empty", Detail: "Set the directory server hostname or IP."})
		return finalize(res)
	}

	// Stage 1 — reachability + TLS/port detection.
	tlsChoice := detectTLSAndPort(ctx, host, cfg, add)
	if tlsChoice == nil {
		return finalize(res) // nothing reachable
	}

	// Stage 2 — bind.
	conn, bindErr := dialAndBind(ctx, host, tlsChoice.port, tlsChoice.useTLS, cfg)
	if bindErr != nil {
		add(Finding{Stage: "bind", Severity: SeverityError,
			Title: "Bind failed",
			Detail: "Connected, but authenticating with the bind DN/password failed: " + bindErr.Error() +
				". For Active Directory the bind DN is usually user@domain (e.g. openidx@corp.local) or DOMAIN\\\\user.",
			Evidence: map[string]any{"bind_dn": cfg.BindDN}})
		return finalize(res)
	}
	defer conn.Close()
	add(Finding{Stage: "bind", Severity: SeverityOK, Title: "Bind succeeded",
		Evidence: map[string]any{"bind_dn": cfg.BindDN}})

	// Stage 3 — discover naming context / base DN + AD-vs-OpenLDAP.
	isAD, baseDN := discoverBaseDN(conn)
	if isAD {
		add(Finding{Stage: "server", Severity: SeverityInfo,
			Title:     "Server detected: Active Directory",
			Suggested: map[string]any{"directory_type": "active_directory"},
			Evidence:  map[string]any{"default_naming_context": baseDN}})
	}
	// Base DN suggestion when missing/blank.
	if strings.TrimSpace(cfg.BaseDN) == "" && baseDN != "" {
		add(Finding{Stage: "base_dn", Severity: SeverityError,
			Title:     "Base DN is empty",
			Detail:    "No search base configured; sync cannot find any objects. Detected the server's default naming context.",
			Suggested: map[string]any{"base_dn": baseDN, "user_base_dn": baseDN, "group_base_dn": baseDN},
			Evidence:  map[string]any{"detected": baseDN}})
	}
	effectiveBase := firstNonEmptyTrim(cfg.UserBaseDN, cfg.BaseDN, baseDN)

	// Stage 4 — user filter + attribute mapping.
	diagnoseUserFilter(conn, isAD, effectiveBase, cfg, add)

	// Stage 5 — group filter.
	diagnoseGroupFilter(conn, isAD, firstNonEmptyTrim(cfg.GroupBaseDN, cfg.BaseDN, baseDN), cfg, add)

	return finalize(res)
}

// tlsChoice is the reachability/TLS outcome.
type tlsChoice struct {
	port   int
	useTLS bool
}

// detectTLSAndPort probes the configured port and, when the TLS/port combo is
// wrong, the standard AD ports (636 LDAPS, 389 LDAP), suggesting a fix.
func detectTLSAndPort(ctx context.Context, host string, cfg LDAPConfig, add func(Finding)) *tlsChoice {
	port := cfg.Port
	if port == 0 {
		port = 389
	}

	// Is the configured port even open?
	if !portOpen(ctx, host, port) {
		// Try the standard alternatives.
		for _, cand := range []struct {
			p      int
			useTLS bool
		}{{636, true}, {389, false}} {
			if cand.p != port && portOpen(ctx, host, cand.p) {
				add(Finding{Stage: "reachability", Severity: SeverityError,
					Title:     fmt.Sprintf("Port %d is not reachable", port),
					Detail:    fmt.Sprintf("Port %d is closed/filtered, but port %d is open. Use it.", port, cand.p),
					Suggested: map[string]any{"port": cand.p, "use_tls": cand.useTLS}})
				return &tlsChoice{port: cand.p, useTLS: cand.useTLS}
			}
		}
		add(Finding{Stage: "reachability", Severity: SeverityError,
			Title:  fmt.Sprintf("Cannot reach %s:%d", host, port),
			Detail: "No LDAP port is reachable (checked configured port, 636, 389). Check host, firewall, and network path."})
		return nil
	}

	// Port is open. Does the TLS setting match the port's protocol?
	// 636 => implicit TLS (LDAPS); 389 => plaintext or StartTLS.
	if port == 636 && !cfg.UseTLS {
		add(Finding{Stage: "tls", Severity: SeverityError,
			Title:     "Port 636 requires TLS",
			Detail:    "Port 636 is LDAPS (implicit TLS) but use_tls is off. Enabling TLS.",
			Suggested: map[string]any{"use_tls": true}})
		return &tlsChoice{port: port, useTLS: true}
	}
	if port == 389 && cfg.UseTLS {
		// Implicit TLS on 389 will fail; prefer 636, else StartTLS.
		if portOpen(ctx, host, 636) {
			add(Finding{Stage: "tls", Severity: SeverityError,
				Title:     "Implicit TLS on port 389 will fail",
				Detail:    "use_tls (implicit TLS/LDAPS) is on but the port is 389 (plaintext). Port 636 is open — use it for LDAPS.",
				Suggested: map[string]any{"port": 636}})
			return &tlsChoice{port: 636, useTLS: true}
		}
		add(Finding{Stage: "tls", Severity: SeverityError,
			Title:     "Implicit TLS on port 389 will fail",
			Detail:    "use_tls (implicit TLS) is on but the port is 389. Use StartTLS on 389 instead, or open 636 for LDAPS.",
			Suggested: map[string]any{"use_tls": false, "start_tls": true}})
		return &tlsChoice{port: port, useTLS: false}
	}

	add(Finding{Stage: "reachability", Severity: SeverityOK,
		Title:    fmt.Sprintf("%s:%d reachable", host, port),
		Evidence: map[string]any{"port": port, "use_tls": cfg.UseTLS}})
	return &tlsChoice{port: port, useTLS: cfg.UseTLS}
}

func portOpen(ctx context.Context, host string, port int) bool {
	d := net.Dialer{Timeout: probeTimeout}
	dctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dialAndBind connects with the resolved TLS/port and binds. skip_tls_verify is
// honored (self-signed AD certs are common).
func dialAndBind(ctx context.Context, host string, port int, useTLS bool, cfg LDAPConfig) (*ldap.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify, ServerName: host} //nolint:gosec // operator opt-in for self-signed AD
	var conn *ldap.Conn
	var err error
	if useTLS {
		conn, err = ldap.DialTLS("tcp", addr, tlsCfg) //nolint:staticcheck
	} else {
		conn, err = ldap.Dial("tcp", addr) //nolint:staticcheck
		if err == nil && cfg.StartTLS {
			if serr := conn.StartTLS(tlsCfg); serr != nil {
				conn.Close()
				return nil, fmt.Errorf("StartTLS failed: %w", serr)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(probeTimeout)
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// discoverBaseDN reads the RootDSE to find the default naming context and detect
// Active Directory (which exposes defaultNamingContext / dsServiceName).
func discoverBaseDN(conn *ldap.Conn) (isAD bool, baseDN string) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(probeTimeout.Seconds()), false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "namingContexts", "dsServiceName", "vendorName"}, nil)
	sr, err := conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return false, ""
	}
	e := sr.Entries[0]
	baseDN = e.GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = e.GetAttributeValue("rootDomainNamingContext")
	}
	if baseDN == "" {
		if ncs := e.GetAttributeValues("namingContexts"); len(ncs) > 0 {
			baseDN = ncs[0]
		}
	}
	// AD exposes dsServiceName and defaultNamingContext; OpenLDAP does not.
	if e.GetAttributeValue("dsServiceName") != "" || e.GetAttributeValue("defaultNamingContext") != "" {
		isAD = true
	}
	return isAD, baseDN
}

const (
	adUserFilter  = "(&(objectClass=user)(objectCategory=person))"
	adGroupFilter = "(objectClass=group)"
)

// diagnoseUserFilter checks that the user filter returns objects and that the
// mapped username/email attributes are actually populated, suggesting AD-correct
// values when they are not.
func diagnoseUserFilter(conn *ldap.Conn, isAD bool, baseDN string, cfg LDAPConfig, add func(Finding)) {
	if baseDN == "" {
		add(Finding{Stage: "user_filter", Severity: SeverityWarn, Title: "Skipped user probe",
			Detail: "No base DN available to search."})
		return
	}
	filter := firstNonEmptyTrim(cfg.UserFilter, defaultUserFilter(isAD))
	count, sample := countAndSample(conn, baseDN, filter, adSampleAttrs())

	// If the configured filter finds nothing but the AD-standard one does, suggest it.
	if count == 0 {
		if isAD {
			adCount, adSample := countAndSample(conn, baseDN, adUserFilter, adSampleAttrs())
			if adCount > 0 {
				add(Finding{Stage: "user_filter", Severity: SeverityError,
					Title: "User filter matches 0 users (wrong filter for Active Directory)",
					Detail: "The configured user filter returns no objects, but the Active Directory standard filter does. " +
						"An OpenLDAP-style filter like (objectClass=inetOrgPerson) never matches AD users.",
					Suggested: map[string]any{"user_filter": adUserFilter},
					Evidence:  map[string]any{"configured_count": 0, "ad_filter_count": adCount}})
				suggestAttributeMapping(adSample, isAD, cfg, add)
				return
			}
		}
		add(Finding{Stage: "user_filter", Severity: SeverityError,
			Title:    "User filter matches 0 users",
			Detail:   "No user objects found under the base DN with this filter. Check the base DN and user filter.",
			Evidence: map[string]any{"base_dn": baseDN, "filter": filter}})
		return
	}

	add(Finding{Stage: "user_filter", Severity: SeverityOK,
		Title:    fmt.Sprintf("User filter matches %d users", count),
		Evidence: map[string]any{"count": count, "filter": filter}})
	suggestAttributeMapping(sample, isAD, cfg, add)
}

// suggestAttributeMapping inspects sample entries and warns when the mapped
// username/email attributes are empty across the sample, suggesting the
// attribute that IS populated (the classic AD "mail is empty, use UPN" trap).
func suggestAttributeMapping(sample []*ldap.Entry, isAD bool, cfg LDAPConfig, add func(Finding)) {
	if len(sample) == 0 {
		return
	}
	m := fillDefaults(cfg.AttributeMapping)

	// Username.
	if pct := populatedPct(sample, m.Username); pct == 0 {
		alt := bestPopulated(sample, []string{"sAMAccountName", "uid", "cn", "userPrincipalName"})
		if alt != "" {
			add(Finding{Stage: "attribute_mapping", Severity: SeverityError,
				Title:     fmt.Sprintf("Username attribute %q is empty on all sampled users", m.Username),
				Detail:    fmt.Sprintf("None of the sampled users have %q. %q is populated — use it for the username.", m.Username, alt),
				Suggested: map[string]any{"attribute_mapping.username": alt}})
		}
	}

	// Email — the big AD trap: mail empty, userPrincipalName populated.
	if pct := populatedPct(sample, m.Email); pct == 0 {
		// For email, any attribute populated on a meaningful share of users is a
		// better choice than one empty on everyone. Prefer UPN for AD.
		alt := mostPopulated(sample, []string{"userPrincipalName", "mail", "proxyAddresses"})
		if alt != "" && alt != m.Email {
			sev := SeverityError
			detail := fmt.Sprintf("None of the sampled users have %q populated, so every user would be skipped (email is required). "+
				"%q is populated — use it for email.", m.Email, alt)
			if isAD && alt == "userPrincipalName" {
				detail = "In Active Directory the 'mail' attribute is frequently empty while userPrincipalName (login@domain) is set on every user. " +
					"Mapping email to userPrincipalName avoids skipping every user."
			}
			add(Finding{Stage: "attribute_mapping", Severity: sev,
				Title:     fmt.Sprintf("Email attribute %q is empty on all sampled users", m.Email),
				Detail:    detail,
				Suggested: map[string]any{"attribute_mapping.email": alt}})
		}
	}
}

// diagnoseGroupFilter checks the group filter returns objects.
func diagnoseGroupFilter(conn *ldap.Conn, isAD bool, baseDN string, cfg LDAPConfig, add func(Finding)) {
	if baseDN == "" {
		return
	}
	filter := firstNonEmptyTrim(cfg.GroupFilter, defaultGroupFilter(isAD))
	count, _ := countAndSample(conn, baseDN, filter, []string{"cn"})
	if count == 0 && isAD {
		adCount, _ := countAndSample(conn, baseDN, adGroupFilter, []string{"cn"})
		if adCount > 0 {
			add(Finding{Stage: "group_filter", Severity: SeverityWarn,
				Title: "Group filter matches 0 groups (wrong filter for Active Directory)",
				Detail: "The configured group filter returns nothing, but the AD standard (objectClass=group) does. " +
					"(objectClass=groupOfNames) is OpenLDAP; AD uses (objectClass=group).",
				Suggested: map[string]any{"group_filter": adGroupFilter, "member_attribute": "member"},
				Evidence:  map[string]any{"ad_filter_count": adCount}})
			return
		}
	}
	if count > 0 {
		add(Finding{Stage: "group_filter", Severity: SeverityOK,
			Title:    fmt.Sprintf("Group filter matches %d groups", count),
			Evidence: map[string]any{"count": count}})
	}
}

// --- helpers ---

func defaultUserFilter(isAD bool) string {
	if isAD {
		return adUserFilter
	}
	return "(objectClass=inetOrgPerson)"
}

func defaultGroupFilter(isAD bool) string {
	if isAD {
		return adGroupFilter
	}
	return "(objectClass=groupOfNames)"
}

func adSampleAttrs() []string {
	return []string{"sAMAccountName", "userPrincipalName", "mail", "uid", "cn", "givenName", "sn", "displayName"}
}

// countAndSample runs a bounded search and returns the total match count (up to
// the search size limit) plus a representative sample. The sample is larger than
// the display default so that built-in / disabled directory accounts (which
// often lack mail/UPN) do not dominate the attribute-population analysis.
func countAndSample(conn *ldap.Conn, baseDN, filter string, attrs []string) (int, []*ldap.Entry) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		200, int(probeTimeout.Seconds()), false, filter, attrs, nil)
	sr, err := conn.Search(req)
	if err != nil {
		// Size-limit-exceeded still returns partial results we can use.
		if sr == nil {
			return 0, nil
		}
	}
	entries := sr.Entries
	sample := entries
	if len(sample) > 25 {
		sample = sample[:25]
	}
	return len(entries), sample
}

// populatedPct returns the fraction (0..1) of sample entries where attr is set.
func populatedPct(sample []*ldap.Entry, attr string) float64 {
	if len(sample) == 0 || attr == "" {
		return 0
	}
	n := 0
	for _, e := range sample {
		if strings.TrimSpace(e.GetAttributeValue(attr)) != "" {
			n++
		}
	}
	return float64(n) / float64(len(sample))
}

// bestPopulated returns the first candidate attribute populated on >=50% of the
// sample, preferring the given order.
func bestPopulated(sample []*ldap.Entry, candidates []string) string {
	for _, c := range candidates {
		if populatedPct(sample, c) >= 0.5 {
			return c
		}
	}
	return ""
}

// mostPopulated returns the candidate with the highest population fraction that
// is > 0, breaking ties by the candidates' preference order. Used for email,
// where a partially-populated attribute still beats one empty on everyone.
func mostPopulated(sample []*ldap.Entry, candidates []string) string {
	best := ""
	var bestPct float64
	for _, c := range candidates {
		p := populatedPct(sample, c)
		if p > bestPct {
			best, bestPct = c, p
		}
	}
	if bestPct <= 0 {
		return ""
	}
	return best
}

func firstNonEmptyTrim(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// finalize computes OK + a human summary ordered by severity.
func finalize(res *DiagnoseResult) *DiagnoseResult {
	order := map[Severity]int{SeverityError: 0, SeverityWarn: 1, SeverityInfo: 2, SeverityOK: 3}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return order[res.Findings[i].Severity] < order[res.Findings[j].Severity]
	})
	errs, warns := 0, 0
	for _, f := range res.Findings {
		switch f.Severity {
		case SeverityError:
			errs++
		case SeverityWarn:
			warns++
		}
	}
	res.OK = errs == 0
	switch {
	case errs > 0:
		res.Summary = fmt.Sprintf("%d problem(s) blocking sync, %d warning(s). Apply the suggested fixes.", errs, warns)
	case warns > 0:
		res.Summary = fmt.Sprintf("Ready to sync, with %d warning(s).", warns)
	default:
		res.Summary = "All checks passed — ready to sync."
	}
	if len(res.SuggestedConfig) == 0 {
		res.SuggestedConfig = nil
	}
	return res
}
