package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

// Discovery advertises subject_types_supported = ["public", "pairwise"] when
// OIDCPairwiseSubjects is on, but the live token path hardcoded `sub: userID`.
// The pairwise implementation existed only on OIDCProvider, which nothing
// outside the test helper constructs — so an operator who enabled the flag to
// get pseudonymous subjects silently got public ones. That is a privacy
// setting that reports success while doing nothing.

func TestSubjectFor(t *testing.T) {
	const (
		userA   = "11111111-1111-1111-1111-111111111111"
		userB   = "22222222-2222-2222-2222-222222222222"
		client1 = "client-one"
		client2 = "client-two"
	)

	t.Run("public subject is the raw user id", func(t *testing.T) {
		s := &Service{config: &config.Config{OIDCPairwiseSubjects: false, EncryptionKey: "k"}}
		if got := s.subjectFor(userA, client1); got != userA {
			t.Errorf("got %q, want the raw user id", got)
		}
	})

	t.Run("pairwise subject is not the user id", func(t *testing.T) {
		s := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt"}}
		got := s.subjectFor(userA, client1)
		if got == userA {
			t.Fatal("pairwise enabled but the raw user id was returned — the flag does nothing")
		}
		if got == "" {
			t.Fatal("empty subject")
		}
	})

	t.Run("pairwise differs per client but is stable per pair", func(t *testing.T) {
		s := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt"}}
		a1, a2 := s.subjectFor(userA, client1), s.subjectFor(userA, client2)
		if a1 == a2 {
			t.Error("same subject across clients — correlation is exactly what pairwise prevents")
		}
		if a1 != s.subjectFor(userA, client1) {
			t.Error("subject is not stable for a (user, client) pair")
		}
	})

	t.Run("different users never share a subject at one client", func(t *testing.T) {
		s := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt"}}
		if s.subjectFor(userA, client1) == s.subjectFor(userB, client1) {
			t.Error("two users collided on one subject")
		}
	})

	t.Run("no client context yields the public subject", func(t *testing.T) {
		// Better a stable public subject than an unstable pseudonym.
		s := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt"}}
		if got := s.subjectFor(userA, ""); got != userA {
			t.Errorf("got %q, want the raw user id", got)
		}
	})

	t.Run("the salt matters", func(t *testing.T) {
		s1 := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt-one"}}
		s2 := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt-two"}}
		if s1.subjectFor(userA, client1) == s2.subjectFor(userA, client1) {
			t.Error("subject independent of the install salt — it would be guessable by a relying party")
		}
	})
}

// The OIDCProvider helper and the live path must agree, otherwise a token and
// UserInfo can disagree about who the user is.
func TestOIDCProviderSubjectMatchesLivePath(t *testing.T) {
	s := &Service{config: &config.Config{OIDCPairwiseSubjects: true, EncryptionKey: "salt"}}
	p := &OIDCProvider{service: s}

	const userID, clientID = "user-1", "client-1"
	if got, want := p.generateSubject(userID, clientID), s.subjectFor(userID, clientID); got != want {
		t.Errorf("provider subject %q != live subject %q", got, want)
	}
}
