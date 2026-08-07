// Package access - Production hardening features for ZitiManager
package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
)

// ZitiCertificate represents a certificate tracked in the ziti_certificates table
type ZitiCertificate struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	CertType             string     `json:"cert_type"`
	Subject              string     `json:"subject"`
	Issuer               string     `json:"issuer"`
	SerialNumber         string     `json:"serial_number"`
	Fingerprint          string     `json:"fingerprint"`
	NotBefore            *time.Time `json:"not_before"`
	NotAfter             *time.Time `json:"not_after"`
	AutoRenew            bool       `json:"auto_renew"`
	RenewalThresholdDays int        `json:"renewal_threshold_days"`
	Status               string     `json:"status"`
	AssociatedIdentityID *string    `json:"associated_identity_id,omitempty"`
	DaysUntilExpiry      int        `json:"days_until_expiry,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// Package-level registry of circuit breakers keyed by controller URL
var (
	circuitBreakersMu sync.Mutex
	circuitBreakers   = make(map[string]*resilience.CircuitBreaker)
)

// circuitBreaker returns or lazily creates a CircuitBreaker for this ZitiManager's
// controller URL. Since we cannot modify the ZitiManager struct, circuit breakers
// are stored in a package-level map keyed by the controller URL.
func (zm *ZitiManager) circuitBreaker() *resilience.CircuitBreaker {
	circuitBreakersMu.Lock()
	defer circuitBreakersMu.Unlock()

	key := zm.cfg.ZitiCtrlURL
	if cb, ok := circuitBreakers[key]; ok {
		return cb
	}

	cb := resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
		Name:         "ziti-controller",
		Threshold:    5,
		ResetTimeout: 30 * time.Second,
		Logger:       zm.logger.With(zap.String("component", "circuit-breaker")),
	})
	circuitBreakers[key] = cb
	return cb
}

// ---- Certificate Management ----

// ListZitiCertificates returns all tracked Ziti certificates with computed days until expiry
func (zm *ZitiManager) ListZitiCertificates(ctx context.Context) ([]ZitiCertificate, error) {
	// Scope to the request's org for admin callers; the background expiry monitor
	// calls this with no org context and reconciles certs across all orgs.
	orgFilter := ""
	args := []interface{}{}
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgFilter = " WHERE org_id = $1"
		args = append(args, org.ID)
	}
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore org filter applied via orgFilter when a request org is present; background expiry monitor reconciles all orgs
		`SELECT id, name, cert_type, subject, issuer, serial_number, fingerprint,
		        not_before, not_after, auto_renew, renewal_threshold_days, status,
		        associated_identity_id, created_at, updated_at
		 FROM ziti_certificates`+orgFilter+`
		 ORDER BY not_after ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query ziti_certificates: %w", err)
	}
	defer rows.Close()

	var certs []ZitiCertificate
	now := time.Now()

	for rows.Next() {
		var cert ZitiCertificate
		err := rows.Scan(
			&cert.ID, &cert.Name, &cert.CertType, &cert.Subject, &cert.Issuer,
			&cert.SerialNumber, &cert.Fingerprint, &cert.NotBefore, &cert.NotAfter,
			&cert.AutoRenew, &cert.RenewalThresholdDays, &cert.Status,
			&cert.AssociatedIdentityID, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
		}

		if cert.NotAfter != nil {
			cert.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
		}

		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return certs, nil
}

// GetCertificateExpiryAlerts returns certificates that are expiring within the given threshold days
func (zm *ZitiManager) GetCertificateExpiryAlerts(ctx context.Context, thresholdDays int) ([]ZitiCertificate, error) {
	threshold := time.Now().Add(time.Duration(thresholdDays) * 24 * time.Hour)

	// Scope to the request's org for admin callers; the background expiry monitor
	// calls this with no org context and alerts across all orgs.
	orgFilter := ""
	args := []interface{}{threshold}
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgFilter = " AND org_id = $2"
		args = append(args, org.ID)
	}
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore org filter applied via orgFilter when a request org is present; background expiry monitor alerts across all orgs
		`SELECT id, name, cert_type, subject, issuer, serial_number, fingerprint,
		        not_before, not_after, auto_renew, renewal_threshold_days, status,
		        associated_identity_id, created_at, updated_at
		 FROM ziti_certificates
		 WHERE not_after IS NOT NULL AND not_after <= $1 AND status = 'active'`+orgFilter+`
		 ORDER BY not_after ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []ZitiCertificate
	now := time.Now()

	for rows.Next() {
		var cert ZitiCertificate
		err := rows.Scan(
			&cert.ID, &cert.Name, &cert.CertType, &cert.Subject, &cert.Issuer,
			&cert.SerialNumber, &cert.Fingerprint, &cert.NotBefore, &cert.NotAfter,
			&cert.AutoRenew, &cert.RenewalThresholdDays, &cert.Status,
			&cert.AssociatedIdentityID, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
		}

		if cert.NotAfter != nil {
			cert.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
		}

		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return certs, nil
}

// RotateCertificate handles certificate rotation based on certificate type.
// For identity certificates, it triggers Ziti re-enrollment. For CA certificates,
// rotation must be done manually (logged as warning).
func (zm *ZitiManager) RotateCertificate(ctx context.Context, certID string) error {
	// Mark the old certificate as rotating
	tag, err := zm.db.Pool.Exec(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; keyed by globally-unique Ziti controller cert id
		`UPDATE ziti_certificates SET status = 'rotating', updated_at = NOW() WHERE id = $1 AND status = 'active'`,
		certID)
	if err != nil {
		return fmt.Errorf("failed to mark certificate as rotating: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate %s not found or not in active status", certID)
	}

	// Fetch the old certificate details
	var name, certType string
	var associatedIdentityID *string
	err = zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; keyed by globally-unique Ziti controller cert id
		`SELECT name, cert_type, associated_identity_id FROM ziti_certificates WHERE id = $1`, certID).
		Scan(&name, &certType, &associatedIdentityID)
	if err != nil {
		zm.revertCertStatus(ctx, certID)
		return fmt.Errorf("failed to read certificate details: %w", err)
	}

	switch certType {
	case "identity":
		if associatedIdentityID == nil {
			zm.revertCertStatus(ctx, certID)
			return fmt.Errorf("identity certificate %s has no associated identity", certID)
		}
		if err := zm.rotateIdentityCert(ctx, certID, *associatedIdentityID, name); err != nil {
			zm.revertCertStatus(ctx, certID)
			return fmt.Errorf("identity cert rotation failed: %w", err)
		}

	case "ca":
		zm.logger.Warn("CA certificate rotation must be done manually",
			zap.String("cert_id", certID), zap.String("name", name))
		zm.revertCertStatus(ctx, certID)
		return fmt.Errorf("CA certificates cannot be auto-rotated; perform manual rotation via the Ziti controller")

	default:
		// For unknown types, attempt identity-style rotation if identity is linked
		if associatedIdentityID != nil {
			if err := zm.rotateIdentityCert(ctx, certID, *associatedIdentityID, name); err != nil {
				zm.revertCertStatus(ctx, certID)
				return fmt.Errorf("cert rotation failed: %w", err)
			}
		} else {
			zm.revertCertStatus(ctx, certID)
			return fmt.Errorf("cannot auto-rotate certificate of type %q without an associated identity", certType)
		}
	}

	return nil
}

// rotateIdentityCert triggers a re-enrollment for a Ziti identity and updates the certificate records.
func (zm *ZitiManager) rotateIdentityCert(ctx context.Context, certID, associatedIdentityID, name string) error {
	// Look up the Ziti controller identity ID from our internal identity table
	var zitiID string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; identity keyed by globally-unique Ziti controller identity id
		"SELECT ziti_id FROM ziti_identities WHERE id = $1", associatedIdentityID).
		Scan(&zitiID)
	if err != nil {
		return fmt.Errorf("failed to look up ziti_id for identity %s: %w", associatedIdentityID, err)
	}

	// Trigger re-enrollment via the Ziti management API
	_, statusCode, err := zm.mgmtRequest("POST",
		fmt.Sprintf("/edge/management/v1/identities/%s/re-enroll", zitiID), nil)
	if err != nil {
		return fmt.Errorf("Ziti re-enrollment API call failed: %w", err)
	}
	if statusCode != 200 && statusCode != 201 && statusCode != 204 {
		return fmt.Errorf("Ziti re-enrollment returned status %d", statusCode)
	}

	// Mark old certificate as rotated
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; keyed by globally-unique Ziti controller cert id
		`UPDATE ziti_certificates SET status = 'rotated', updated_at = NOW() WHERE id = $1`,
		certID)
	if err != nil {
		zm.logger.Warn("Failed to mark old certificate as rotated", zap.String("cert_id", certID), zap.Error(err))
	}

	// Create a new active certificate record (real cert data will be synced by SyncCertificatesFromController)
	newID := uuid.New().String()
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; placeholder cert keyed by globally-unique Ziti controller identity id
		`INSERT INTO ziti_certificates (id, name, cert_type, subject, issuer, serial_number, fingerprint,
		                                auto_renew, renewal_threshold_days, status, associated_identity_id,
		                                created_at, updated_at)
		 VALUES ($1, $2, 'identity', 'pending-sync', 'pending-sync', '', '', true, 30, 'active', $3, NOW(), NOW())`,
		newID, name+"-renewed", associatedIdentityID)
	if err != nil {
		zm.logger.Warn("Failed to create renewed certificate placeholder", zap.Error(err))
	}

	// Log the rotation event to audit
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; system actor, keyed by globally-unique Ziti controller cert id
		`INSERT INTO audit_events (id, event_type, actor_id, target_type, resource_id, details, created_at)
		 VALUES ($1, 'certificate.rotate', 'system', 'ziti_certificate', $2, $3, NOW())`,
		uuid.New().String(), certID,
		fmt.Sprintf(`{"old_cert_id":"%s","new_cert_id":"%s","name":"%s","ziti_identity":"%s","method":"re-enrollment"}`,
			certID, newID, name, zitiID))
	if err != nil {
		zm.logger.Warn("Failed to log certificate rotation audit event", zap.Error(err))
	}

	zm.logger.Info("Certificate rotation completed via Ziti re-enrollment",
		zap.String("old_cert_id", certID),
		zap.String("new_cert_id", newID),
		zap.String("ziti_identity", zitiID),
		zap.String("name", name))

	return nil
}

// revertCertStatus reverts a certificate from 'rotating' back to 'active' on failure.
func (zm *ZitiManager) revertCertStatus(ctx context.Context, certID string) {
	_, err := zm.db.Pool.Exec(ctx,
		//orgscope:ignore background/auto cert rotation reachable from expiry monitor; keyed by globally-unique Ziti controller cert id
		`UPDATE ziti_certificates SET status = 'active', updated_at = NOW() WHERE id = $1 AND status = 'rotating'`,
		certID)
	if err != nil {
		zm.logger.Error("Failed to revert certificate status", zap.String("cert_id", certID), zap.Error(err))
	}
}

// SyncCertificatesFromController fetches CA and identity certificates from the Ziti controller
// and upserts them into the ziti_certificates table.
func (zm *ZitiManager) SyncCertificatesFromController(ctx context.Context) error {
	zm.logger.Info("Syncing certificates from Ziti controller")

	// Fetch CAs from the controller
	caData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/cas?limit=1000", nil)
	if err != nil {
		return fmt.Errorf("failed to fetch CAs from controller: %w", err)
	}
	if statusCode != 200 {
		return fmt.Errorf("unexpected status %d fetching CAs", statusCode)
	}

	var caResp struct {
		Data []struct {
			ID                 string `json:"id"`
			Name               string `json:"name"`
			Fingerprint        string `json:"fingerprint"`
			CertPEM            string `json:"certPem"`
			IsVerified         bool   `json:"isVerified"`
			IsAutoCaEnrollment bool   `json:"isAutoCaEnrollmentEnabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(caData, &caResp); err != nil {
		return fmt.Errorf("failed to parse CA response: %w", err)
	}

	for _, ca := range caResp.Data {
		fingerprint := ca.Fingerprint
		if fingerprint == "" {
			hash := sha256.Sum256([]byte(ca.CertPEM))
			fingerprint = hex.EncodeToString(hash[:])
		}

		_, err := zm.db.Pool.Exec(ctx,
			//orgscope:ignore install-wide Ziti controller certificate sync across all orgs; CA keyed by globally-unique Ziti controller CA id
			`INSERT INTO ziti_certificates (id, name, cert_type, subject, issuer, serial_number,
			                                fingerprint, auto_renew, renewal_threshold_days,
			                                status, created_at, updated_at)
			 VALUES ($1, $2, 'ca', $3, $3, '', $4, false, 30, 'active', NOW(), NOW())
			 ON CONFLICT (id) DO UPDATE SET
			    name = EXCLUDED.name, fingerprint = EXCLUDED.fingerprint, updated_at = NOW()`,
			ca.ID, ca.Name, ca.Name, fingerprint)
		if err != nil {
			zm.logger.Warn("Failed to upsert CA certificate", zap.String("ca_id", ca.ID), zap.Error(err))
		}
	}

	// Fetch identity certificates
	identData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/identities?limit=1000", nil)
	if err != nil {
		return fmt.Errorf("failed to fetch identities from controller: %w", err)
	}
	if statusCode != 200 {
		return fmt.Errorf("unexpected status %d fetching identities", statusCode)
	}

	var identResp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(identData, &identResp); err != nil {
		return fmt.Errorf("failed to parse identities response: %w", err)
	}

	for _, ident := range identResp.Data {
		certID := "cert-" + ident.ID
		identID := ident.ID

		_, err := zm.db.Pool.Exec(ctx,
			//orgscope:ignore install-wide Ziti controller certificate sync across all orgs; identity cert keyed by globally-unique Ziti controller identity id
			`INSERT INTO ziti_certificates (id, name, cert_type, subject, issuer, serial_number,
			                                fingerprint, auto_renew, renewal_threshold_days,
			                                status, associated_identity_id, created_at, updated_at)
			 VALUES ($1, $2, 'identity', $3, 'ziti-controller', '', '', false, 30, 'active', $4, NOW(), NOW())
			 ON CONFLICT (id) DO UPDATE SET
			    name = EXCLUDED.name, associated_identity_id = EXCLUDED.associated_identity_id, updated_at = NOW()`,
			certID, ident.Name+"-cert", ident.Name, &identID)
		if err != nil {
			zm.logger.Warn("Failed to upsert identity certificate",
				zap.String("identity_id", ident.ID), zap.Error(err))
		}
	}

	zm.logger.Info("Certificate sync complete",
		zap.Int("cas_synced", len(caResp.Data)),
		zap.Int("identities_synced", len(identResp.Data)))

	return nil
}

// StartCertificateMonitor launches a background goroutine that periodically checks for
// expiring certificates, logs warnings, and auto-rotates certificates that have auto_renew enabled.
func (zm *ZitiManager) StartCertificateMonitor(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		zm.logger.Info("Certificate expiry monitor started")

		for {
			select {
			case <-ctx.Done():
				zm.logger.Info("Certificate expiry monitor stopped")
				return
			case <-ticker.C:
				zm.checkCertificateExpiry(ctx)
			}
		}
	}()
}

// checkCertificateExpiry is the internal routine that inspects certificate expiry
// and triggers rotation for auto-renewable certificates.
func (zm *ZitiManager) checkCertificateExpiry(ctx context.Context) {
	certs, err := zm.ListZitiCertificates(ctx)
	if err != nil {
		zm.logger.Error("Certificate monitor failed to list certificates", zap.Error(err))
		return
	}

	now := time.Now()
	for _, cert := range certs {
		if cert.Status != "active" || cert.NotAfter == nil {
			continue
		}

		daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)
		threshold := cert.RenewalThresholdDays
		if threshold <= 0 {
			threshold = 30
		}

		if daysUntil <= threshold {
			zm.logger.Warn("Certificate approaching expiry",
				zap.String("cert_id", cert.ID),
				zap.String("name", cert.Name),
				zap.String("cert_type", cert.CertType),
				zap.Int("days_until_expiry", daysUntil),
				zap.Time("not_after", *cert.NotAfter))

			if cert.AutoRenew {
				zm.logger.Info("Auto-rotating certificate",
					zap.String("cert_id", cert.ID),
					zap.String("name", cert.Name))

				if err := zm.RotateCertificate(ctx, cert.ID); err != nil {
					zm.logger.Error("Auto-rotation failed for certificate",
						zap.String("cert_id", cert.ID),
						zap.String("name", cert.Name),
						zap.Error(err))
				}
			}
		}
	}
}

// ---- Graceful Degradation ----

// MgmtRequestWithCircuitBreaker wraps mgmtRequest with the circuit breaker pattern.
// If the circuit is open, requests are rejected immediately without contacting the controller.
func (zm *ZitiManager) MgmtRequestWithCircuitBreaker(method, path string, body []byte) ([]byte, int, error) {
	cb := zm.circuitBreaker()

	var respData []byte
	var statusCode int

	_, err := cb.Execute(func() (interface{}, error) {
		var reqErr error
		respData, statusCode, reqErr = zm.mgmtRequest(method, path, body)
		if reqErr != nil {
			return nil, reqErr
		}
		// Treat 5xx as failures for circuit breaker purposes
		if statusCode >= 500 {
			return nil, fmt.Errorf("controller returned server error: HTTP %d", statusCode)
		}
		return nil, nil
	})

	return respData, statusCode, err
}

// IsControllerAvailable returns whether the Ziti controller is considered available
// based on the circuit breaker state, without making an actual request.
func (zm *ZitiManager) IsControllerAvailable() bool {
	cb := zm.circuitBreaker()
	return cb.State() != resilience.StateOpen
}
