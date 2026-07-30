package dbproxy

// SCRAM-SHA-256 client authentication for the upstream leg (RFC 5802 / RFC
// 7677), so the proxy can authenticate to real PostgreSQL servers — which use
// scram-sha-256 by default since PG 14. This is the client half only (the proxy
// acts as a SCRAM client toward the upstream); the proxy's own client-facing
// auth stays cleartext-token (the operator presents an OpenIDX broker token).
//
// Channel binding (SCRAM-SHA-256-PLUS) is not used: the proxy→upstream hop is a
// plain TCP connection in this cut (a trusted network path in the broker's
// deployment), so we negotiate the non-PLUS mechanism with gs2 header "n,,".

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// scramClient carries the state of an in-progress SCRAM-SHA-256 exchange.
type scramClient struct {
	password    string
	clientNonce string
	firstBare   string // client-first-message-bare (without gs2 header)
	authMessage string // built across the exchange for the final proof
	serverProof []byte // expected ServerSignature to verify the final message
}

// newScramClient starts a SCRAM-SHA-256 exchange and returns the client-first
// message to send in the SASLInitialResponse.
func newScramClient(password string) (*scramClient, string, error) {
	nonce, err := scramNonce()
	if err != nil {
		return nil, "", err
	}
	c := &scramClient{password: password, clientNonce: nonce}
	c.firstBare = "n=,r=" + nonce
	// gs2 header "n,," = no channel binding, no authzid.
	clientFirst := "n,," + c.firstBare
	return c, clientFirst, nil
}

// step processes the server-first message and returns the client-final message
// (with the client proof). It also stores the expected ServerSignature so the
// caller can verify the server-final message.
func (c *scramClient) step(serverFirst string) (string, error) {
	attrs, err := parseSCRAMAttrs(serverFirst)
	if err != nil {
		return "", err
	}
	serverNonce := attrs["r"]
	saltB64 := attrs["s"]
	iterStr := attrs["i"]
	if serverNonce == "" || saltB64 == "" || iterStr == "" {
		return "", errors.New("scram: server-first missing r/s/i")
	}
	if !strings.HasPrefix(serverNonce, c.clientNonce) {
		return "", errors.New("scram: server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", fmt.Errorf("scram: bad salt: %w", err)
	}
	iters, err := strconv.Atoi(iterStr)
	if err != nil || iters <= 0 {
		return "", fmt.Errorf("scram: bad iteration count %q", iterStr)
	}

	// client-final-message-without-proof. Channel binding "biws" = base64("n,,").
	clientFinalNoProof := "c=biws,r=" + serverNonce
	c.authMessage = c.firstBare + "," + serverFirst + "," + clientFinalNoProof

	saltedPassword := pbkdf2.Key([]byte(c.password), salt, iters, sha256.Size, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSHA256(storedKey[:], []byte(c.authMessage))

	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}

	// Server signature we expect back in the server-final message.
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	c.serverProof = hmacSHA256(serverKey, []byte(c.authMessage))

	return clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// verify checks the server-final message's ServerSignature (v=) against the one
// we computed. A mismatch means the server did not prove knowledge of the
// password — a MITM / misconfiguration; fail closed.
func (c *scramClient) verify(serverFinal string) error {
	attrs, err := parseSCRAMAttrs(serverFinal)
	if err != nil {
		return err
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil {
		return fmt.Errorf("scram: bad server signature: %w", err)
	}
	if !hmac.Equal(got, c.serverProof) {
		return errors.New("scram: server signature mismatch")
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// scramNonce returns a base64 client nonce.
func scramNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// parseSCRAMAttrs parses "k=v,k=v" SCRAM attribute lists.
func parseSCRAMAttrs(s string) (map[string]string, error) {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("scram: bad attribute %q", part)
		}
		out[k] = v
	}
	return out, nil
}
