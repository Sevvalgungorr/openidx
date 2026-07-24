// SSH certificate authority + session brokering (migration v109) — the
// `openidx connect` substrate (Wave C1).
//
// Instead of distributing standing SSH keys, OpenIDX acts as an SSH CA: each
// org has one CA keypair (private key held envelope-encrypted in the vault,
// only the public key stored). A user asks the broker to connect to a host and
// gets back a SHORT-LIVED, principal-scoped SSH user certificate. Hosts trust
// exactly one CA public key (TrustedUserCAKeys); revocation is automatic by
// expiry. Every issuance is recorded in brokered_sessions, the ledger that also
// covers DB/K8s brokering.
package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// sshCertDefaultTTL / sshCertMaxTTL bound how long an issued certificate is
// valid. Short by design — the cert IS the session lease.
const (
	sshCertDefaultTTL = 10 * time.Minute
	sshCertMaxTTL     = 60 * time.Minute
)

// sshCARecord is the stored CA metadata (public half only).
type sshCARecord struct {
	PublicKey     string `json:"public_key"`
	KeyType       string `json:"key_type"`
	vaultSecretID string
}

// loadSSHCA reads the org's CA record, or pgx.ErrNoRows when uninitialized.
func (s *Service) loadSSHCA(c *gin.Context, orgID string) (*sshCARecord, error) {
	var rec sshCARecord
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT public_key, key_type, vault_secret_id::text FROM ssh_ca WHERE org_id = $1`, orgID).
		Scan(&rec.PublicKey, &rec.KeyType, &rec.vaultSecretID)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// caSigner reveals the CA private key from the vault and returns an ssh.Signer.
// The PEM bytes are zeroed after parsing.
func (s *Service) caSigner(c *gin.Context, orgID, userID string, rec *sshCARecord) (ssh.Signer, error) {
	pemBytes, err := s.vaultSvc.Reveal(c.Request.Context(), rec.vaultSecretID, userID,
		pamCallerRoles(c), "ssh-ca sign", true)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range pemBytes {
			pemBytes[i] = 0
		}
	}()
	return ssh.ParsePrivateKey(pemBytes)
}

// handleInitSSHCA — POST /pam/ssh-ca/init (admin). Generates the org CA keypair
// if absent (idempotent: returns the existing public key when already set) and
// stores the private key in the vault. The returned public key goes into each
// host's TrustedUserCAKeys.
func (s *Service) handleInitSSHCA(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
		return
	}
	userID := c.GetString("user_id")

	// Already initialized → return the existing public key (idempotent).
	if rec, err := s.loadSSHCA(c, org.ID); err == nil {
		c.JSON(http.StatusOK, gin.H{"public_key": rec.PublicKey, "key_type": rec.KeyType, "already_initialized": true})
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("handleInitSSHCA: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check CA state"})
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.logger.Error("handleInitSSHCA: keygen failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate CA key"})
		return
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal CA public key"})
		return
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	pemBlock, err := ssh.MarshalPrivateKey(priv, "openidx-ssh-ca")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal CA private key"})
		return
	}
	privPEM := pem.EncodeToMemory(pemBlock)

	// Store the private key in the vault (envelope-encrypted). Store zeroes the
	// input slice on return.
	meta, err := s.vaultSvc.Store(ctx, vault.StoreInput{
		Name:        "ssh-ca:" + org.ID,
		Type:        "ssh_ca",
		Description: "OpenIDX SSH certificate-authority private key",
		Value:       privPEM,
		CreatedBy:   userID,
	})
	if err != nil {
		s.logger.Error("handleInitSSHCA: vault store failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store CA key"})
		return
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ssh_ca (org_id, public_key, key_type, vault_secret_id, created_by)
		VALUES ($1,$2,'ssh-ed25519',$3,NULLIF($4,'')::uuid)`,
		org.ID, authorized, meta.ID, userID); err != nil {
		// Best-effort cleanup of the orphaned secret.
		_ = s.vaultSvc.Delete(ctx, meta.ID)
		s.logger.Error("handleInitSSHCA: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist CA"})
		return
	}
	s.logAuditEvent(c, "pam.ssh_ca_initialized", org.ID, "ssh_ca", map[string]interface{}{"user_id": userID})
	c.JSON(http.StatusCreated, gin.H{"public_key": authorized, "key_type": "ssh-ed25519"})
}

// handleGetSSHCA — GET /pam/ssh-ca. Returns the org CA public key (the value to
// install as TrustedUserCAKeys on target hosts). No secret material.
func (s *Service) handleGetSSHCA(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rec, err := s.loadSSHCA(c, org.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "SSH CA not initialized"})
			return
		}
		s.logger.Error("handleGetSSHCA: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load CA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"public_key":      rec.PublicKey,
		"key_type":        rec.KeyType,
		"trusted_ca_line": "@cert-authority * " + rec.PublicKey,
	})
}

// sshConnectReq is the body of a connect request.
type sshConnectReq struct {
	Host       string `json:"host" binding:"required"`
	Principal  string `json:"principal" binding:"required"` // the login on the host
	PublicKey  string `json:"public_key"`                   // optional BYO key (authorized_keys line)
	Reason     string `json:"reason"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// handleSSHConnect — POST /pam/connect/ssh. Signs a short-lived SSH user
// certificate for the caller and records the brokered session. If the caller
// supplies no public key, an ephemeral keypair is generated and the private key
// is returned once (never stored).
func (s *Service) handleSSHConnect(c *gin.Context) {
	var req sshConnectReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host and principal are required"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
		return
	}

	rec, err := s.loadSSHCA(c, org.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusPreconditionRequired, gin.H{"error": "SSH CA not initialized; POST /pam/ssh-ca/init first"})
			return
		}
		s.logger.Error("handleSSHConnect: CA lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load CA"})
		return
	}

	// Resolve the user public key: BYO or ephemeral.
	var userPub ssh.PublicKey
	var ephemeralPrivPEM []byte
	if strings.TrimSpace(req.PublicKey) != "" {
		pk, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "public_key is not a valid authorized_keys entry"})
			return
		}
		userPub = pk
	} else {
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate session key"})
			return
		}
		userPub, err = ssh.NewPublicKey(pub)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal session key"})
			return
		}
		blk, merr := ssh.MarshalPrivateKey(priv, "openidx-session")
		if merr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal session key"})
			return
		}
		ephemeralPrivPEM = pem.EncodeToMemory(blk)
	}

	signer, err := s.caSigner(c, org.ID, userID, rec)
	if err != nil {
		s.logger.Error("handleSSHConnect: CA signer failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load CA signer"})
		return
	}

	ttl := sshCertDefaultTTL
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
		if ttl > sshCertMaxTTL {
			ttl = sshCertMaxTTL
		}
	}
	now := time.Now()
	serial := sshCertSerial()
	keyID := "openidx:" + userID + ":" + req.Principal
	cert := &ssh.Certificate{
		Key:             userPub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":     "",
				"permit-user-rc": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		s.logger.Error("handleSSHConnect: sign failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign certificate"})
		return
	}
	certAuthorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	expiresAt := now.Add(ttl)
	var sessionID string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO brokered_sessions (org_id, user_id, target_type, target, principal, cert_serial, cert_key_id, reason, expires_at)
		VALUES ($1,$2,'ssh',$3,$4,$5,$6,NULLIF($7,''),$8)
		RETURNING id`,
		org.ID, userID, req.Host, req.Principal, int64(serial), keyID, req.Reason, expiresAt).Scan(&sessionID); err != nil {
		s.logger.Error("handleSSHConnect: session record failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record session"})
		return
	}
	s.logAuditEvent(c, "pam.ssh_cert_issued", sessionID, "brokered_session", map[string]interface{}{
		"host": req.Host, "principal": req.Principal, "user_id": userID, "serial": serial, "ttl_minutes": int(ttl.Minutes()),
	})

	resp := gin.H{
		"session_id":  sessionID,
		"certificate": certAuthorized,
		"principal":   req.Principal,
		"expires_at":  expiresAt,
	}
	if ephemeralPrivPEM != nil {
		resp["private_key"] = string(ephemeralPrivPEM)
		for i := range ephemeralPrivPEM {
			ephemeralPrivPEM[i] = 0
		}
	}
	c.JSON(http.StatusOK, resp)
}

// brokerSessionReq registers a non-SSH brokered session (db/k8s).
type brokerSessionReq struct {
	TargetType string `json:"target_type" binding:"required"` // db|k8s
	Target     string `json:"target" binding:"required"`
	Principal  string `json:"principal" binding:"required"`
	Reason     string `json:"reason"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// handleBrokerSession — POST /pam/brokered-sessions. Records a brokered DB/K8s
// session (the credential-issuance hook for those targets rides on the existing
// credentials rotators). SSH goes through /pam/connect/ssh instead.
func (s *Service) handleBrokerSession(c *gin.Context) {
	var req brokerSessionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_type, target and principal are required"})
		return
	}
	if req.TargetType != "db" && req.TargetType != "k8s" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_type must be 'db' or 'k8s' (use /pam/connect/ssh for ssh)"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	ttl := sshCertDefaultTTL
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
		if ttl > sshCertMaxTTL {
			ttl = sshCertMaxTTL
		}
	}
	expiresAt := time.Now().Add(ttl)
	var sessionID string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO brokered_sessions (org_id, user_id, target_type, target, principal, reason, expires_at)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7)
		RETURNING id`,
		org.ID, userID, req.TargetType, req.Target, req.Principal, req.Reason, expiresAt).Scan(&sessionID); err != nil {
		s.logger.Error("handleBrokerSession: record failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record session"})
		return
	}
	s.logAuditEvent(c, "pam.session_brokered", sessionID, "brokered_session", map[string]interface{}{
		"target_type": req.TargetType, "target": req.Target, "principal": req.Principal, "user_id": userID,
	})
	c.JSON(http.StatusCreated, gin.H{"session_id": sessionID, "expires_at": expiresAt})
}

// BrokeredSession is the API view of a brokered_sessions row.
type BrokeredSession struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	TargetType string     `json:"target_type"`
	Target     string     `json:"target"`
	Principal  string     `json:"principal"`
	Reason     string     `json:"reason,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// handleListBrokeredSessions — GET /pam/brokered-sessions (admin). Retires
// expired sessions first so the live list is accurate.
func (s *Service) handleListBrokeredSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE brokered_sessions SET status = 'expired', ended_at = NOW()
		 WHERE org_id = $1 AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()`, org.ID)

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id::text, target_type, target, principal, COALESCE(reason,''), status, started_at, expires_at
		  FROM brokered_sessions WHERE org_id = $1 ORDER BY started_at DESC LIMIT 500`, org.ID)
	if err != nil {
		s.logger.Error("handleListBrokeredSessions: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()
	out := []BrokeredSession{}
	for rows.Next() {
		var b BrokeredSession
		if err := rows.Scan(&b.ID, &b.UserID, &b.TargetType, &b.Target, &b.Principal, &b.Reason,
			&b.Status, &b.StartedAt, &b.ExpiresAt); err != nil {
			s.logger.Warn("handleListBrokeredSessions: scan failed", zap.Error(err))
			continue
		}
		out = append(out, b)
	}
	c.JSON(http.StatusOK, gin.H{"sessions": out})
}

// handleEndBrokeredSession — POST /pam/brokered-sessions/:id/end. Marks a
// session ended (an admin may end anyone's; a user may end their own).
func (s *Service) handleEndBrokeredSession(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	principalFilter := userID
	if s.pamCallerIsAdmin(c) {
		principalFilter = ""
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE brokered_sessions SET status = 'ended', ended_at = NOW()
		 WHERE id = $1 AND org_id = $2 AND status = 'active'
		   AND ($3 = '' OR user_id = NULLIF($3,'')::uuid)`,
		c.Param("id"), org.ID, principalFilter)
	if err != nil {
		s.logger.Error("handleEndBrokeredSession: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end session"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "active session not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": "ended"})
}

// sshCertSerial returns a random 63-bit certificate serial. Serials are
// informational (the brokered_sessions row id is the authority); 63 bits of
// crypto/rand makes a collision astronomically unlikely, and clearing the top
// bit keeps the value within a signed BIGINT (the cert_serial column) so it is
// never stored as a negative number.
func sshCertSerial() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) & 0x7FFFFFFFFFFFFFFF
}
