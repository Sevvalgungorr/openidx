package oauth

import (
	"testing"
)

// TestEmailDomainAllowed pins the domain restriction an administrator sets on a
// social login button. The restriction previously existed only as a stored
// column that nothing read, so these cases describe what "restricted to my
// company domain" must actually mean.
func TestEmailDomainAllowed(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		email   string
		want    bool
	}{
		{
			name:    "no restriction admits anyone",
			domains: nil,
			email:   "someone@gmail.com",
			want:    true,
		},
		{
			name:    "listed domain is admitted",
			domains: []string{"corp.example"},
			email:   "ayse@corp.example",
			want:    true,
		},
		{
			name:    "unlisted domain is refused",
			domains: []string{"corp.example"},
			email:   "attacker@gmail.com",
			want:    false,
		},
		{
			name:    "matching is case insensitive on both sides",
			domains: []string{"CORP.example"},
			email:   "Ayse@Corp.EXAMPLE",
			want:    true,
		},
		{
			name:    "configured domain may be written with a leading @",
			domains: []string{"@corp.example"},
			email:   "ayse@corp.example",
			want:    true,
		},
		{
			// A lookalike domain that merely ends with the allowed one must not
			// pass, otherwise "corp.example" would admit "evil-corp.example".
			name:    "suffix lookalike is refused",
			domains: []string{"corp.example"},
			email:   "attacker@evil-corp.example",
			want:    false,
		},
		{
			// Subdomains are a different namespace and are not implied.
			name:    "subdomain is not implied",
			domains: []string{"corp.example"},
			email:   "attacker@mail.corp.example",
			want:    false,
		},
		{
			// Providers such as GitHub may withhold the address entirely. A
			// restricted button cannot verify the domain, so it must refuse.
			name:    "missing email is refused when restricted",
			domains: []string{"corp.example"},
			email:   "",
			want:    false,
		},
		{
			name:    "malformed address without a domain is refused",
			domains: []string{"corp.example"},
			email:   "ayse@",
			want:    false,
		},
		{
			// Multiple "@" appear in quoted local parts; the domain is what
			// follows the final one.
			name:    "domain is taken from the final at sign",
			domains: []string{"corp.example"},
			email:   "\"odd@name\"@corp.example",
			want:    true,
		},
		{
			name:    "any of several listed domains is admitted",
			domains: []string{"corp.example", "subsidiary.example"},
			email:   "mehmet@subsidiary.example",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := socialProviderPolicy{allowedDomains: normalizeDomains(tc.domains)}
			if got := p.emailDomainAllowed(tc.email); got != tc.want {
				t.Errorf("emailDomainAllowed(%q) with %v = %v, want %v",
					tc.email, tc.domains, got, tc.want)
			}
		})
	}
}

// TestNormalizeDomains checks that blank configuration collapses to "no
// restriction" rather than to a list that refuses everybody, which would lock
// an organisation out of its own provider.
func TestNormalizeDomains(t *testing.T) {
	if got := normalizeDomains([]string{"", "   ", "@"}); got != nil {
		t.Errorf("blank domain configuration should mean no restriction, got %v", got)
	}
	got := normalizeDomains([]string{" Corp.Example ", "@Other.example"})
	if len(got) != 2 || got[0] != "corp.example" || got[1] != "other.example" {
		t.Errorf("normalizeDomains = %v, want [corp.example other.example]", got)
	}
}
