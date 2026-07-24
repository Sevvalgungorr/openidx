package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// End-to-end crypto proof (no DB): mint a CA, sign a short-lived user cert for a
// principal exactly as handleSSHConnect does, and verify a host's CertChecker
// accepts it for that principal and rejects a different one. This locks the
// actual certificate semantics the feature depends on.
func TestSSHCA_signAndVerifyUserCert(t *testing.T) {
	t.Parallel()

	// CA keypair + signer (mirrors handleInitSSHCA).
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}

	// Ephemeral user key (mirrors the no-BYO-key path).
	userPubEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("user keygen: %v", err)
	}
	userPub, err := ssh.NewPublicKey(userPubEd)
	if err != nil {
		t.Fatalf("user pub: %v", err)
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userPub,
		Serial:          sshCertSerial(),
		CertType:        ssh.UserCert,
		KeyId:           "openidx:user-1:deploy",
		ValidPrincipals: []string{"deploy"},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(sshCertDefaultTTL).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	// A host trusting this CA must accept the cert for "deploy"...
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caSigner.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("valid cert rejected for its principal: %v", err)
	}
	// ...and reject it for a principal it was not issued for.
	if err := checker.CheckCert("root", cert); err == nil {
		t.Fatalf("cert wrongly accepted for a principal it does not carry")
	}

	// The marshaled cert must be a valid authorized_keys cert line.
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	if !strings.Contains(line, "cert-v01@openssh.com") {
		t.Fatalf("marshaled cert is not an openssh cert line: %q", line)
	}
}

// The CA private key round-trips through the PEM marshal/parse the vast store
// path uses, so caSigner can reload it.
func TestSSHCA_privateKeyPEMRoundTrip(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "openidx-ssh-ca")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(blk))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Fatalf("unexpected key type %q", signer.PublicKey().Type())
	}
}

// Serials must be distinct across rapid successive issuance (the low bits come
// from crypto/rand, so same-nanosecond calls still differ).
func TestSSHCertSerial_distinct(t *testing.T) {
	t.Parallel()
	seen := map[uint64]bool{}
	for i := 0; i < 1000; i++ {
		s := sshCertSerial()
		if seen[s] {
			t.Fatalf("duplicate serial %d at i=%d", s, i)
		}
		seen[s] = true
	}
}

// handleSSHConnect must reject a body missing host/principal before any work.
func TestHandleSSHConnect_validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, body := range []string{``, `{}`, `{"host":"h"}`, `{"principal":"p"}`} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/pam/connect/ssh",
			strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		s.handleSSHConnect(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

// handleBrokerSession must reject 'ssh' (that belongs on /pam/connect/ssh) and
// any unknown target_type, after the required-fields bind.
func TestHandleBrokerSession_targetTypeGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, body := range []string{
		`{"target_type":"ssh","target":"h","principal":"p"}`,
		`{"target_type":"ftp","target":"h","principal":"p"}`,
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/pam/brokered-sessions",
			strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		s.handleBrokerSession(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

// The SSH-CA / broker endpoints must fail closed (403) without an org context.
func TestSSHCA_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	handlers := map[string]func(*gin.Context){
		"get-ca":        s.handleGetSSHCA,
		"list-sessions": s.handleListBrokeredSessions,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/pam/"+name, nil)
			h(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s without org context: got %d, want 403", name, w.Code)
			}
		})
	}
}
