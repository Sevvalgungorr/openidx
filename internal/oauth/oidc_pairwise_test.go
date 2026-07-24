package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

// generateSubject must return the public subject (raw user id) by default and a
// stable, per-client pairwise pseudonym when OIDCPairwiseSubjects is on — the same
// value for a given (client, user) and different across clients (OIDC Core §8.1).
func TestGenerateSubject_Pairwise(t *testing.T) {
	logger := testLogger()
	user := "user-123"
	clientA := "client-a"
	clientB := "client-b"

	// Default: pairwise off → public subject for every client.
	svcPublic := &Service{issuer: "https://t", config: &config.Config{OIDCPairwiseSubjects: false, EncryptionKey: "0123456789abcdef0123456789abcdef"}}
	pPublic := NewOIDCProvider(svcPublic, localMockIdentityService(t), logger, "https://t")
	if got := pPublic.generateSubject(user, clientA); got != user {
		t.Errorf("public: got %q, want raw user id %q", got, user)
	}
	if pPublic.generateSubject(user, clientA) != pPublic.generateSubject(user, clientB) {
		t.Error("public subject must be identical across clients")
	}

	// Pairwise on.
	svcPair := &Service{issuer: "https://t", config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "0123456789abcdef0123456789abcdef"}}
	pPair := NewOIDCProvider(svcPair, localMockIdentityService(t), logger, "https://t")

	subA1 := pPair.generateSubject(user, clientA)
	subA2 := pPair.generateSubject(user, clientA)
	subB := pPair.generateSubject(user, clientB)

	if subA1 == user {
		t.Error("pairwise subject must not be the raw user id")
	}
	if subA1 != subA2 {
		t.Error("pairwise subject must be stable for the same (client, user)")
	}
	if subA1 == subB {
		t.Error("pairwise subject must differ across clients (privacy)")
	}
	// Empty client always falls back to public (callers without client context).
	if got := pPair.generateSubject(user, ""); got != user {
		t.Errorf("empty client must yield public subject, got %q", got)
	}
	// Different users under the same client must differ.
	if pPair.generateSubject("other-user", clientA) == subA1 {
		t.Error("different users must map to different pairwise subjects")
	}
}

// Discovery must advertise "pairwise" only when it's actually enabled — never
// advertise a subject type we don't honor ("advertised = working").
func TestDiscoverySubjectTypes(t *testing.T) {
	off := &Service{config: &config.Config{OIDCPairwiseSubjects: false}}
	if got := off.discoverySubjectTypes(); len(got) != 1 || got[0] != "public" {
		t.Errorf("flag off: got %v, want [public]", got)
	}
	on := &Service{config: &config.Config{OIDCPairwiseSubjects: true}}
	got := on.discoverySubjectTypes()
	if len(got) != 2 || got[0] != "public" || got[1] != "pairwise" {
		t.Errorf("flag on: got %v, want [public pairwise]", got)
	}
	// nil config must not panic and defaults to public-only.
	nilCfg := &Service{}
	if got := nilCfg.discoverySubjectTypes(); len(got) != 1 || got[0] != "public" {
		t.Errorf("nil config: got %v, want [public]", got)
	}
}
