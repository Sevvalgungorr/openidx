package access

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/access/edr"
	"go.uber.org/zap"
)

// This file implements the EDR/MDM posture ingestion store + worker. It reads
// device compliance from an external EDR/MDM (via internal/access/edr), maps
// each device to a local Ziti identity, and writes a posture result into
// device_posture_results — the exact table the proxy / continuous-verify
// enforcement already reads. So a device CrowdStrike marks "contained" (or
// Intune marks non-compliant) fails its posture check and gets revoked off the
// overlay automatically, with no new enforcement code.

// EDRSource is a configured EDR/MDM connection.
type EDRSource struct {
	ID                  string     `json:"id"`
	OrgID               string     `json:"org_id,omitempty"`
	Name                string     `json:"name"`
	Provider            string     `json:"provider"`
	BaseURL             string     `json:"base_url,omitempty"`
	ClientID            string     `json:"client_id,omitempty"`
	TenantID            string     `json:"tenant_id,omitempty"`
	APIUser             string     `json:"api_user,omitempty"`
	PostureCheckID      string     `json:"posture_check_id,omitempty"`
	MatchStrategy       string     `json:"match_strategy"`
	ResultTTLMinutes    int        `json:"result_ttl_minutes"`
	PollIntervalMinutes int        `json:"poll_interval_minutes"`
	Enabled             bool       `json:"enabled"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty"`
	LastSyncStatus      string     `json:"last_sync_status,omitempty"`
	LastSyncError       string     `json:"last_sync_error,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// EDRSourceInput is the create/update payload (secrets plaintext, encrypted at rest).
type EDRSourceInput struct {
	Name                string `json:"name"`
	Provider            string `json:"provider"`
	BaseURL             string `json:"base_url,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
	ClientSecret        string `json:"client_secret,omitempty"`
	TenantID            string `json:"tenant_id,omitempty"`
	APIUser             string `json:"api_user,omitempty"`
	APIToken            string `json:"api_token,omitempty"`
	PostureCheckID      string `json:"posture_check_id,omitempty"`
	MatchStrategy       string `json:"match_strategy,omitempty"`
	ResultTTLMinutes    int    `json:"result_ttl_minutes,omitempty"`
	PollIntervalMinutes int    `json:"poll_interval_minutes,omitempty"`
	Enabled             bool   `json:"enabled"`
}

func validEDRProvider(p string) bool {
	return p == edr.ProviderCrowdStrike || p == edr.ProviderIntune ||
		p == edr.ProviderJamf || p == edr.ProviderWazuh
}

func validMatchStrategy(m string) bool {
	return m == "serial" || m == "hostname" || m == "email"
}

func (s *Service) edrEncrypt(plaintext string) (string, error) {
	if plaintext == "" || s.idpCipher == nil {
		return plaintext, nil
	}
	return s.idpCipher.Encrypt(plaintext)
}

func (s *Service) edrDecrypt(stored string) (string, error) {
	if stored == "" || s.idpCipher == nil {
		return stored, nil
	}
	return s.idpCipher.Decrypt(stored)
}

// CreateEDRSource validates + persists an EDR source, encrypting secrets.
func (s *Service) CreateEDRSource(ctx context.Context, orgID string, in *EDRSourceInput) (*EDRSource, error) {
	if in.Name == "" || in.Provider == "" {
		return nil, fmt.Errorf("name and provider are required")
	}
	if !validEDRProvider(in.Provider) {
		return nil, fmt.Errorf("unsupported provider %q (want crowdstrike|intune|jamf|wazuh)", in.Provider)
	}
	if in.MatchStrategy == "" {
		// Wazuh agents report no serial/email; the agent name is the endpoint
		// hostname, so hostname is the only strategy that can ever match.
		if in.Provider == edr.ProviderWazuh {
			in.MatchStrategy = "hostname"
		} else {
			in.MatchStrategy = "serial"
		}
	}
	if !validMatchStrategy(in.MatchStrategy) {
		return nil, fmt.Errorf("unsupported match_strategy %q (want serial|hostname|email)", in.MatchStrategy)
	}
	if in.ResultTTLMinutes <= 0 {
		in.ResultTTLMinutes = 60
	}
	if in.PollIntervalMinutes <= 0 {
		in.PollIntervalMinutes = 15
	}
	secretEnc, err := s.edrEncrypt(in.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt client secret: %w", err)
	}
	tokenEnc, err := s.edrEncrypt(in.APIToken)
	if err != nil {
		return nil, fmt.Errorf("encrypt api token: %w", err)
	}
	id := uuid.NewString()
	_, err = s.db.Pool.Exec(ctx, `
        INSERT INTO edr_posture_sources
            (id, org_id, name, provider, base_url, client_id, client_secret_enc,
             tenant_id, api_user, api_token_enc, posture_check_id, match_strategy,
             result_ttl_minutes, poll_interval_minutes, enabled)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		id, edrNullIfEmpty(orgID), in.Name, in.Provider, edrNullIfEmpty(in.BaseURL),
		edrNullIfEmpty(in.ClientID), secretEnc, edrNullIfEmpty(in.TenantID),
		edrNullIfEmpty(in.APIUser), tokenEnc, edrNullUUID(in.PostureCheckID),
		in.MatchStrategy, in.ResultTTLMinutes, in.PollIntervalMinutes, in.Enabled)
	if err != nil {
		return nil, fmt.Errorf("insert edr source: %w", err)
	}
	return s.GetEDRSource(ctx, orgID, id)
}

// GetEDRSource loads a source (secrets never returned).
func (s *Service) GetEDRSource(ctx context.Context, orgID, id string) (*EDRSource, error) {
	row := s.db.Pool.QueryRow(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, provider, COALESCE(base_url,''),
               COALESCE(client_id,''), COALESCE(tenant_id,''), COALESCE(api_user,''),
               COALESCE(posture_check_id::text,''), match_strategy, result_ttl_minutes,
               poll_interval_minutes, enabled, last_sync_at,
               COALESCE(last_sync_status,''), COALESCE(last_sync_error,''),
               created_at, updated_at
          FROM edr_posture_sources
         WHERE id=$1 AND (org_id::text=$2 OR $2='')`, id, orgID)
	return scanEDRSource(row)
}

// ListEDRSources lists sources for an org.
func (s *Service) ListEDRSources(ctx context.Context, orgID string) ([]EDRSource, error) {
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, provider, COALESCE(base_url,''),
               COALESCE(client_id,''), COALESCE(tenant_id,''), COALESCE(api_user,''),
               COALESCE(posture_check_id::text,''), match_strategy, result_ttl_minutes,
               poll_interval_minutes, enabled, last_sync_at,
               COALESCE(last_sync_status,''), COALESCE(last_sync_error,''),
               created_at, updated_at
          FROM edr_posture_sources
         WHERE (org_id::text=$1 OR $1='')
         ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EDRSource
	for rows.Next() {
		src, err := scanEDRSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *src)
	}
	return out, rows.Err()
}

// DeleteEDRSource removes a source (+ its device mappings via CASCADE).
func (s *Service) DeleteEDRSource(ctx context.Context, orgID, id string) error {
	ct, err := s.db.Pool.Exec(ctx,
		`DELETE FROM edr_posture_sources WHERE id=$1 AND (org_id::text=$2 OR $2='')`, id, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("edr source not found")
	}
	return nil
}

// connectorForSource builds a live connector for a source, decrypting secrets.
func (s *Service) connectorForSource(ctx context.Context, id string) (edr.Connector, *EDRSource, error) {
	var provider, baseURL, clientID, tenantID, apiUser string
	var secretEnc, tokenEnc *string
	if err := s.db.Pool.QueryRow(ctx, `
        SELECT provider, COALESCE(base_url,''), COALESCE(client_id,''), COALESCE(tenant_id,''),
               COALESCE(api_user,''), client_secret_enc, api_token_enc
          FROM edr_posture_sources WHERE id=$1`, id).
		Scan(&provider, &baseURL, &clientID, &tenantID, &apiUser, &secretEnc, &tokenEnc); err != nil {
		return nil, nil, fmt.Errorf("load edr source: %w", err)
	}
	secret := ""
	if secretEnc != nil {
		if v, err := s.edrDecrypt(*secretEnc); err == nil {
			secret = v
		}
	}
	token := ""
	if tokenEnc != nil {
		if v, err := s.edrDecrypt(*tokenEnc); err == nil {
			token = v
		}
	}
	conn, err := edr.New(edr.Config{
		Provider: provider, BaseURL: baseURL, ClientID: clientID, ClientSecret: secret,
		TenantID: tenantID, APIUser: apiUser, APIToken: token,
	})
	if err != nil {
		return nil, nil, err
	}
	src, _ := s.GetEDRSource(ctx, "", id)
	return conn, src, nil
}

func edrNullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func edrNullUUID(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

type edrRowScanner interface {
	Scan(dest ...interface{}) error
}

func scanEDRSource(row edrRowScanner) (*EDRSource, error) {
	var s EDRSource
	if err := row.Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Provider, &s.BaseURL, &s.ClientID, &s.TenantID,
		&s.APIUser, &s.PostureCheckID, &s.MatchStrategy, &s.ResultTTLMinutes,
		&s.PollIntervalMinutes, &s.Enabled, &s.LastSyncAt, &s.LastSyncStatus,
		&s.LastSyncError, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

// edrSourceStatus is used to serialize the ingestion result for the admin UI.
type edrSourceStatus struct {
	SourceID       string `json:"source_id"`
	DevicesSeen    int    `json:"devices_seen"`
	DevicesMatched int    `json:"devices_matched"`
	PostureFailed  int    `json:"posture_failed"`
	PosturePassed  int    `json:"posture_passed"`
}

// syncEDRSource runs one ingestion pass for a source: pull devices, map each to
// a local Ziti identity, and record a posture result (pass/fail) so existing
// enforcement acts on it. Returns a status summary.
func (s *Service) syncEDRSource(ctx context.Context, sourceID string) (*edrSourceStatus, error) {
	conn, src, err := s.connectorForSource(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if src.PostureCheckID == "" {
		return nil, fmt.Errorf("source has no posture_check_id; cannot record results")
	}
	devices, err := conn.ListDevices(ctx)
	if err != nil {
		s.markEDRSyncError(ctx, sourceID, err)
		return nil, err
	}

	status := &edrSourceStatus{SourceID: sourceID}
	ttl := time.Duration(src.ResultTTLMinutes) * time.Minute
	zm := s.ziti()

	for _, d := range devices {
		status.DevicesSeen++
		identityID := s.resolveIdentityForDevice(ctx, src, d)
		// Persist/refresh the mapping regardless of match, for the admin UI.
		s.upsertEDRMapping(ctx, src, d, identityID)
		if identityID == "" {
			continue // no local identity yet; can't enforce
		}
		status.DevicesMatched++

		passed := d.Passing()
		if passed {
			status.PosturePassed++
		} else {
			status.PostureFailed++
		}
		if zm == nil {
			continue // no Ziti manager wired (e.g. overlay disabled)
		}
		expires := time.Now().Add(ttl)
		details := map[string]interface{}{
			"source":      src.Provider,
			"external_id": d.ExternalID,
			"compliant":   d.Compliant,
			"risk":        d.Risk,
			"last_seen":   d.LastSeen,
		}
		for k, v := range d.Raw {
			details["raw_"+k] = v
		}
		_ = zm.RecordPostureResult(ctx, &PostureCheckResult{
			IdentityID: identityID,
			CheckID:    src.PostureCheckID,
			Passed:     passed,
			Details:    details,
			CheckedAt:  time.Now().UTC(),
			ExpiresAt:  &expires,
		})
	}

	s.markEDRSyncOK(ctx, sourceID, status)
	return status, nil
}

// resolveIdentityForDevice maps an EDR device to a ziti_identities.id using the
// source's match strategy against users, returning "" if unmatched.
func (s *Service) resolveIdentityForDevice(ctx context.Context, src *EDRSource, d edr.Device) string {
	var matchVal, query string
	switch src.MatchStrategy {
	case "email":
		matchVal = d.Email
		query = `SELECT zi.id::text FROM ziti_identities zi JOIN users u ON u.id = zi.user_id
                 WHERE lower(u.email) = lower($1) LIMIT 1`
	case "hostname":
		matchVal = d.Hostname
		// enrolled_agents stores device attributes in a JSONB metadata blob;
		// match the reported hostname to the enrolling user's Ziti identity.
		query = `SELECT zi.id::text FROM ziti_identities zi
                 JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id
                 WHERE lower(ea.metadata->>'hostname') = lower($1) LIMIT 1`
	default: // serial
		matchVal = d.Serial
		query = `SELECT zi.id::text FROM ziti_identities zi
                 JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id
                 WHERE ea.metadata->>'serial' = $1 LIMIT 1`
	}
	if matchVal == "" {
		return ""
	}
	var identityID string
	if err := s.db.Pool.QueryRow(ctx, query, matchVal).Scan(&identityID); err != nil {
		return ""
	}
	return identityID
}

func (s *Service) upsertEDRMapping(ctx context.Context, src *EDRSource, d edr.Device, identityID string) {
	var matchVal string
	switch src.MatchStrategy {
	case "email":
		matchVal = d.Email
	case "hostname":
		matchVal = d.Hostname
	default:
		matchVal = d.Serial
	}
	_, _ = s.db.Pool.Exec(ctx, `
        INSERT INTO edr_device_mappings
            (org_id, source_id, external_device_id, match_value, identity_id,
             last_compliant, last_risk, last_seen_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7, NULLIF($8,'')::timestamptz)
        ON CONFLICT (source_id, external_device_id)
        DO UPDATE SET match_value=EXCLUDED.match_value, identity_id=EXCLUDED.identity_id,
                      last_compliant=EXCLUDED.last_compliant, last_risk=EXCLUDED.last_risk,
                      last_seen_at=EXCLUDED.last_seen_at, updated_at=NOW()`,
		edrNullIfEmpty(src.OrgID), src.ID, d.ExternalID, edrNullIfEmpty(matchVal),
		edrNullUUID(identityID), d.Compliant, edrNullIfEmpty(d.Risk), d.LastSeen)
}

func (s *Service) markEDRSyncOK(ctx context.Context, sourceID string, st *edrSourceStatus) {
	summary, _ := json.Marshal(st)
	_, _ = s.db.Pool.Exec(ctx, `
        UPDATE edr_posture_sources
           SET last_sync_at=NOW(), last_sync_status='ok', last_sync_error=NULL, updated_at=NOW()
         WHERE id=$1`, sourceID)
	s.logger.Info("EDR sync complete", zap.String("source", sourceID), zap.ByteString("summary", summary))
}

func (s *Service) markEDRSyncError(ctx context.Context, sourceID string, cause error) {
	_, _ = s.db.Pool.Exec(ctx, `
        UPDATE edr_posture_sources
           SET last_sync_at=NOW(), last_sync_status='error', last_sync_error=$2, updated_at=NOW()
         WHERE id=$1`, sourceID, cause.Error())
}
