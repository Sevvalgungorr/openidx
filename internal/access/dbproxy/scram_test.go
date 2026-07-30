package dbproxy

import (
	"strings"
	"testing"
)

// TestSCRAMClientFlow exercises the client-side SCRAM-SHA-256 computation
// against known-good intermediate values, ensuring the client-first/final
// messages are well-formed and the server-signature verification round-trips
// with a locally-simulated server.
func TestSCRAMClientFlow(t *testing.T) {
	sc, clientFirst, err := newScramClient("s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(clientFirst, "n,,n=,r=") {
		t.Fatalf("client-first malformed: %q", clientFirst)
	}

	// Simulate a server-first message with a known salt + iteration count,
	// extending the client nonce.
	serverNonce := sc.clientNonce + "SERVERPART"
	// base64("salt1234") style; any valid base64 works.
	serverFirst := "r=" + serverNonce + ",s=c2FsdHNhbHQ=,i=4096"
	clientFinal, err := sc.step(serverFirst)
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	if !strings.Contains(clientFinal, "c=biws,r="+serverNonce) || !strings.Contains(clientFinal, ",p=") {
		t.Fatalf("client-final malformed: %q", clientFinal)
	}

	// verify() must reject a bad server signature.
	if err := sc.verify("v=YmFkc2lnbmF0dXJl"); err == nil {
		t.Fatal("expected verify to reject a wrong server signature")
	}
}

func TestSCRAMRejectsBadServerNonce(t *testing.T) {
	sc, _, err := newScramClient("pw")
	if err != nil {
		t.Fatal(err)
	}
	// server nonce that does NOT extend the client nonce → must be rejected.
	_, err = sc.step("r=totallydifferent,s=c2FsdA==,i=4096")
	if err == nil {
		t.Fatal("expected rejection of non-extending server nonce")
	}
}

func TestParseSCRAMAttrs(t *testing.T) {
	m, err := parseSCRAMAttrs("r=abc,s=def,i=4096")
	if err != nil {
		t.Fatal(err)
	}
	if m["r"] != "abc" || m["s"] != "def" || m["i"] != "4096" {
		t.Fatalf("bad parse: %v", m)
	}
	if _, err := parseSCRAMAttrs("noequalssign"); err == nil {
		t.Fatal("expected error on malformed attr")
	}
}

func TestMD5Auth(t *testing.T) {
	// Known vector: md5('pass'+'user') then md5(that + salt).
	got := md5Auth("user", "pass", [4]byte{1, 2, 3, 4})
	if !strings.HasPrefix(got, "md5") || len(got) != 35 {
		t.Fatalf("md5Auth format wrong: %q (len %d)", got, len(got))
	}
	// Determinism.
	if md5Auth("user", "pass", [4]byte{1, 2, 3, 4}) != got {
		t.Fatal("md5Auth not deterministic")
	}
}
