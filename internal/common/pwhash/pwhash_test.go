package pwhash

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !IsArgon2id(h) {
		t.Fatalf("new hash is not argon2id: %q", h)
	}
	if strings.Contains(h, pw) {
		t.Fatalf("hash contains the plaintext")
	}
	ok, rehash, err := Verify(h, pw)
	if err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if rehash {
		t.Fatalf("a freshly written hash asked to be rehashed")
	}
	if ok, _, err := Verify(h, pw+"x"); ok || err != nil {
		t.Fatalf("Verify(wrong): ok=%v err=%v, want false/nil", ok, err)
	}
}

// TestHashFitsTheColumn guards the one thing that would corrupt every new
// credential silently: password_hash is VARCHAR(255), and a hash truncated on
// write can never verify again.
func TestHashFitsTheColumn(t *testing.T) {
	h, err := Hash("some-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) > 255 {
		t.Fatalf("encoded hash is %d bytes, exceeds the VARCHAR(255) column", len(h))
	}
}

func TestSaltIsPerCall(t *testing.T) {
	a, _ := Hash("same-password")
	b, _ := Hash("same-password")
	if a == b {
		t.Fatalf("two hashes of the same password are identical — salt is not random")
	}
	for _, h := range []string{a, b} {
		if ok, _, err := Verify(h, "same-password"); !ok || err != nil {
			t.Fatalf("Verify: ok=%v err=%v", ok, err)
		}
	}
}

// TestBcryptHashesStillVerifyAndAskForUpgrade is the migration path: every
// existing credential is bcrypt, and a deploy that could not read them would
// lock out every user at once.
func TestBcryptHashesStillVerifyAndAskForUpgrade(t *testing.T) {
	const pw = "legacy-password"
	legacy, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := Verify(string(legacy), pw)
	if err != nil {
		t.Fatalf("Verify(bcrypt): %v", err)
	}
	if !ok {
		t.Fatalf("a valid bcrypt credential stopped verifying")
	}
	if !rehash {
		t.Fatalf("bcrypt hash did not report needsRehash, so it would never be upgraded")
	}
	if ok, _, _ := Verify(string(legacy), "wrong"); ok {
		t.Fatalf("bcrypt verify accepted the wrong password")
	}
}

func TestNeedsRehashTracksCost(t *testing.T) {
	const pw = "cost-sensitive"

	weak := Params{Memory: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	wh, err := weak.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := Verify(wh, pw)
	if err != nil || !ok {
		t.Fatalf("weak hash must still verify: ok=%v err=%v", ok, err)
	}
	if !rehash {
		t.Fatalf("a hash below the current cost did not ask to be rehashed")
	}

	// Stronger than Default must NOT be rewritten — that would weaken it.
	strong := Params{Memory: Default.Memory * 2, Iterations: Default.Iterations + 1,
		Parallelism: Default.Parallelism, SaltLength: 16, KeyLength: 32}
	sh, err := strong.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err = Verify(sh, pw)
	if err != nil || !ok {
		t.Fatalf("strong hash must verify: ok=%v err=%v", ok, err)
	}
	if rehash {
		t.Fatalf("a hash stronger than Default was marked for rehash — that downgrades it")
	}
}

// TestLongPassphrasesCanBeHashedAtAll is a concrete gain over bcrypt, and it
// fixes a live defect rather than just strengthening one.
//
// The password policy sets no maximum length, but bcrypt refuses outright to
// hash anything past 72 bytes ("password length exceeds 72 bytes"). So before
// this package a user who chose a long passphrase — exactly the users following
// the advice to prefer length — had their password rejected by an internal
// hashing error that read as a server fault. Argon2id has no such limit.
func TestLongPassphrasesCanBeHashedAtAll(t *testing.T) {
	base := strings.Repeat("a", 72)
	p1, p2 := base+"ONE", base+"TWO"

	h, err := Hash(p1)
	if err != nil {
		t.Fatalf("Argon2id refused a %d-byte passphrase: %v", len(p1), err)
	}
	if ok, _, _ := Verify(h, p1); !ok {
		t.Fatalf("the passphrase that was hashed does not verify")
	}
	if ok, _, _ := Verify(h, p2); ok {
		t.Fatalf("a passphrase differing only after byte 72 verified — the tail is being ignored")
	}

	// Pin the premise: this is what the old path did with the same input.
	if _, berr := bcrypt.GenerateFromPassword([]byte(p1), 4); berr == nil {
		t.Skip("bcrypt now accepts >72-byte passwords; premise changed")
	}
}

// TestUnreadableHashIsAnErrorNotAFailedLogin — reporting a corrupt hash as a
// wrong password would bury an operational fault in normal login noise.
func TestUnreadableHashIsAnErrorNotAFailedLogin(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext-password", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=1,t=1,p=1$", "$argon2id$", "$argon2id$v=19$bogus$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=1,t=1,p=1$!!!not-base64!!!$aGFzaA",
	} {
		ok, rehash, err := Verify(bad, "whatever")
		if err == nil {
			t.Fatalf("Verify(%q) returned no error (ok=%v rehash=%v); a broken hash must not read as a failed login", bad, ok, rehash)
		}
		if ok {
			t.Fatalf("Verify(%q) reported success", bad)
		}
	}
}

// TestUnsupportedArgon2VersionIsRejected — a hash from a future/other Argon2
// version must not be silently compared under the wrong version.
func TestUnsupportedArgon2VersionIsRejected(t *testing.T) {
	h, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(h, "v=19", "v=16", 1)
	if _, _, err := Verify(tampered, "pw"); err == nil {
		t.Fatalf("a hash declaring an unsupported argon2 version was accepted")
	}
}
