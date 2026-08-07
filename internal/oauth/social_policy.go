package oauth

import (
	"context"
	"encoding/json"
	"strings"
)

// Social provider registration policy.
//
// social_providers carries the switches an administrator sets for a social
// login button: which email domains may use it, and whether an unknown visitor
// may be provisioned an account on the spot. Those switches were previously
// only written and read back by the admin CRUD screens; the sign-in path never
// consulted them, so an administrator who restricted a provider to their own
// company domain got no restriction at all, and turning off automatic account
// creation did not stop accounts from being created.
//
// The settings are enforced here, at the point where a social identity is about
// to become (or select) a local user.

// socialProviderPolicy is the administrator's configuration for one social
// login button.
type socialProviderPolicy struct {
	// allowedDomains restricts which email domains may sign in through this
	// provider. Empty means "no restriction", which is the historical
	// behaviour and stays the default when no row is configured.
	allowedDomains []string
	// autoCreateUsers controls whether an unrecognised visitor may be
	// provisioned a local account on first sign-in.
	autoCreateUsers bool
	// configured reports whether an administrator has actually registered this
	// button. When false the caller keeps the permissive legacy behaviour
	// rather than locking everyone out of a working deployment.
	configured bool
}

// loadSocialProviderPolicy reads the administrator's settings for the social
// button attached to this identity provider.
//
// A missing row is not an error: social_providers is the display/config table
// for the login buttons and an identity provider can be used without one. In
// that case the caller keeps the previous behaviour.
func (s *Service) loadSocialProviderPolicy(ctx context.Context, providerID string) (socialProviderPolicy, error) {
	policy := socialProviderPolicy{autoCreateUsers: true}

	var domainsJSON []byte
	var autoCreate *bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT allowed_domains, auto_create_users
		FROM social_providers
		WHERE provider_id = $1
		ORDER BY sort_order NULLS LAST
		LIMIT 1
	`, providerID).Scan(&domainsJSON, &autoCreate)
	if err != nil {
		// No button registered for this provider: keep legacy behaviour.
		return policy, nil
	}

	policy.configured = true
	if autoCreate != nil {
		policy.autoCreateUsers = *autoCreate
	}

	// allowed_domains is jsonb. Accept both a JSON array and a single string so
	// a hand-edited row cannot silently disable the restriction.
	if len(domainsJSON) > 0 {
		var list []string
		if err := json.Unmarshal(domainsJSON, &list); err == nil {
			policy.allowedDomains = normalizeDomains(list)
		} else {
			var single string
			if err := json.Unmarshal(domainsJSON, &single); err == nil && single != "" {
				policy.allowedDomains = normalizeDomains([]string{single})
			}
		}
	}

	return policy, nil
}

// normalizeDomains lowercases and trims configured domains, dropping empties
// and a leading "@" so both "@corp.com" and "corp.com" behave the same.
func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "@")
		if d != "" {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// emailDomainAllowed reports whether an email address may use this provider.
//
// An address with no domain never satisfies a domain restriction. Subdomains
// are not implied: "corp.com" does not admit "evil-corp.com", and matching is
// exact against the part after the final "@".
func (p socialProviderPolicy) emailDomainAllowed(email string) bool {
	if len(p.allowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, allowed := range p.allowedDomains {
		if domain == allowed {
			return true
		}
	}
	return false
}
