package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrVerifyUnsupported means this directory type cannot cheaply verify a credential
// (e.g. Azure AD via Graph). Callers treat it as "skip verification".
var ErrVerifyUnsupported = errors.New("directory: password verify unsupported for this type")

// Service is the directory sync service facade
type Service struct {
	db        *database.PostgresDB
	logger    *zap.Logger
	scheduler *Scheduler
	engine    *SyncEngine
	cancelFn  context.CancelFunc
}

// NewService creates a new directory service
func NewService(db *database.PostgresDB, logger *zap.Logger) *Service {
	engine := NewSyncEngine(db, logger)
	scheduler := NewScheduler(db, engine, logger)

	return &Service{
		db:        db,
		logger:    logger.With(zap.String("service", "directory")),
		scheduler: scheduler,
		engine:    engine,
	}
}

// SetRedis wires a Redis client so the scheduler's tick is leader-gated across
// replicas. Optional — with no client set, the scheduler runs on every instance
// (correct for a single-instance deployment). Call before Start.
func (s *Service) SetRedis(rdb *redis.Client) {
	if s.scheduler != nil {
		s.scheduler.redis = rdb
	}
}

// Start launches the background scheduler
func (s *Service) Start(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	go s.scheduler.Start(ctx)
	s.logger.Info("Directory service started")
	return nil
}

// Stop halts the scheduler
func (s *Service) Stop() {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.scheduler.Stop()
	s.logger.Info("Directory service stopped")
}

// TestConnection tests connectivity for a given directory config
func (s *Service) TestConnection(ctx context.Context, dirType string, configBytes []byte) error {
	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		connector := NewLDAPConnector(cfg, s.logger)
		return connector.TestConnection()
	case "azure_ad":
		var cfg AzureADConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid Azure AD config: %w", err)
		}
		connector := NewAzureADConnector(cfg, s.logger)
		return connector.TestConnection(ctx)
	case "hris", "bamboohr":
		var cfg HRISConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid HRIS config: %w", err)
		}
		connector, err := newHRISConnector(cfg, s.logger)
		if err != nil {
			return err
		}
		return connector.TestConnection(ctx)
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

// TriggerSync manually starts a sync for a directory
func (s *Service) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	return s.scheduler.TriggerSync(ctx, directoryID, fullSync)
}

// Diagnose runs live LDAP/AD probes against the supplied config and returns a
// DiagnoseResult with findings + suggested config fixes. Only meaningful for
// LDAP/Active Directory; other directory types return a single info finding.
func (s *Service) Diagnose(ctx context.Context, dirType string, configBytes []byte) (interface{}, error) {
	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return nil, fmt.Errorf("invalid LDAP config: %w", err)
		}
		return Diagnose(ctx, cfg), nil
	default:
		return &DiagnoseResult{
			OK:      true,
			Summary: "Automated diagnostics are available for LDAP / Active Directory directories.",
			Findings: []Finding{{
				Stage: "server", Severity: SeverityInfo,
				Title:  "Diagnostics not applicable",
				Detail: fmt.Sprintf("Live LDAP/AD probing does not apply to directory type %q. Use the connection test instead.", dirType),
			}},
		}, nil
	}
}

// AuthenticateUser authenticates a user against their directory
func (s *Service) AuthenticateUser(ctx context.Context, directoryID, username, password string) error {
	dirType, configBytes, err := s.loadDirectoryTypeAndConfig(ctx, directoryID)
	if err != nil {
		return err
	}

	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		// The JSON config blob may omit directory_type; the authoritative type
		// lives in the directory_integrations.type column. Propagate it so
		// isActiveDirectory() picks the AD-specific code paths.
		cfg.DirectoryType = dirType
		connector := NewLDAPConnector(cfg, s.logger)
		return connector.AuthenticateUser(username, password)
	case "azure_ad":
		return fmt.Errorf("azure_ad users must authenticate via SSO")
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

// ChangePassword changes a user's password in their directory (user-initiated, requires old password)
func (s *Service) ChangePassword(ctx context.Context, directoryID, username, oldPassword, newPassword string) error {
	dirType, configBytes, err := s.loadDirectoryTypeAndConfig(ctx, directoryID)
	if err != nil {
		return err
	}

	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		// See AuthenticateUser: the DB `type` column is authoritative for
		// AD detection. Active Directory rejects the RFC 3062 Password Modify
		// extended op ("Unknown extended request OID"); setting DirectoryType
		// routes AD through the unicodePwd modify path instead.
		cfg.DirectoryType = dirType
		connector := NewLDAPConnector(cfg, s.logger)
		return connector.ChangePassword(username, oldPassword, newPassword)
	case "azure_ad":
		return fmt.Errorf("password is managed by Azure Active Directory")
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

// ResetPassword resets a user's password in their directory (admin-initiated, no old password needed)
func (s *Service) ResetPassword(ctx context.Context, directoryID, username, newPassword string) error {
	dirType, configBytes, err := s.loadDirectoryTypeAndConfig(ctx, directoryID)
	if err != nil {
		return err
	}

	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		// Authoritative AD detection (see ChangePassword): use unicodePwd modify
		// for AD instead of the unsupported RFC 3062 extended operation.
		cfg.DirectoryType = dirType
		connector := NewLDAPConnector(cfg, s.logger)
		return connector.ResetPassword(username, newPassword)
	case "azure_ad":
		var cfg AzureADConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid Azure AD config: %w", err)
		}
		// For Azure AD, username is actually the user's external_id (Azure objectId)
		// Look up the external_id for this user
		org, err := orgctx.From(ctx)
		if err != nil {
			return err
		}
		var externalID *string
		s.db.Pool.QueryRow(ctx,
			`SELECT external_id FROM users WHERE username = $1 AND directory_id = $2 AND org_id = $3`,
			username, directoryID, org.ID).Scan(&externalID)
		if externalID == nil {
			return fmt.Errorf("user not found in Azure AD directory")
		}
		connector := NewAzureADConnector(cfg, s.logger)
		return connector.ResetPassword(ctx, *externalID, newPassword)
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

// VerifyPassword confirms that username/password authenticates against the directory.
// For ldap/active_directory it performs a bind; for azure_ad it returns ErrVerifyUnsupported.
func (s *Service) VerifyPassword(ctx context.Context, directoryID, username, password string) error {
	dirType, configBytes, err := s.loadDirectoryTypeAndConfig(ctx, directoryID)
	if err != nil {
		return err
	}

	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		connector := NewLDAPConnector(cfg, s.logger)
		return connector.VerifyBind(username, password)
	case "azure_ad":
		return ErrVerifyUnsupported
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

// loadDirectoryTypeAndConfig loads the type and raw config for a directory integration
func (s *Service) loadDirectoryTypeAndConfig(ctx context.Context, directoryID string) (string, []byte, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", nil, err
	}
	var dirType string
	var configBytes []byte
	err = s.db.Pool.QueryRow(ctx,
		`SELECT type, config FROM directory_integrations WHERE id = $1 AND org_id = $2 AND enabled = true`,
		directoryID, org.ID).Scan(&dirType, &configBytes)
	if err != nil {
		return "", nil, fmt.Errorf("directory not found or disabled: %w", err)
	}
	return dirType, configBytes, nil
}

// GetSyncLogs returns recent sync logs for a directory
func (s *Service) GetSyncLogs(ctx context.Context, directoryID string, limit int) ([]SyncLog, error) {
	if limit <= 0 {
		limit = 20
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, directory_id, sync_type, status, started_at, completed_at,
		        users_added, users_updated, users_disabled, groups_added, groups_updated, groups_deleted, error_message
		 FROM directory_sync_logs
		 WHERE directory_id = $1 AND org_id = $3
		 ORDER BY started_at DESC
		 LIMIT $2`, directoryID, limit, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []SyncLog
	for rows.Next() {
		var l SyncLog
		if err := rows.Scan(&l.ID, &l.DirectoryID, &l.SyncType, &l.Status, &l.StartedAt, &l.CompletedAt,
			&l.UsersAdded, &l.UsersUpdated, &l.UsersDisabled, &l.GroupsAdded, &l.GroupsUpdated, &l.GroupsDeleted, &l.ErrorMessage); err != nil {
			continue
		}
		logs = append(logs, l)
	}

	if logs == nil {
		logs = []SyncLog{}
	}
	return logs, nil
}

// GetSyncState returns the current sync state for a directory
func (s *Service) GetSyncState(ctx context.Context, directoryID string) (*SyncState, error) {
	var state SyncState
	state.DirectoryID = directoryID

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at, last_usn_changed, last_modify_timestamp, users_synced, groups_synced, errors_count, sync_duration_ms
		 FROM directory_sync_state WHERE directory_id = $1 AND org_id = $2`, directoryID, org.ID).Scan(
		&state.LastSyncAt, &state.LastUSNChanged, &state.LastModifyTimestamp,
		&state.UsersSynced, &state.GroupsSynced, &state.ErrorsCount, &state.SyncDurationMs)
	if err != nil {
		// No sync state yet — return empty
		return &state, nil
	}

	return &state, nil
}
