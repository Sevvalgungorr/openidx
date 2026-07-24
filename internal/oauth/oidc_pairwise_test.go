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
