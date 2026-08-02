// Package directory provides LDAP/Active Directory/Azure AD synchronization
package directory

import (
	"context"
	"time"
)

// LDAPConfig holds LDAP connection and search configuration
type LDAPConfig struct {
	Host              string           `json:"host"`
	Port              int              `json:"port"`
	UseTLS            bool             `json:"use_tls"`
	StartTLS          bool             `json:"start_tls"`
	SkipTLSVerify     bool             `json:"skip_tls_verify"`
	BindDN            string           `json:"bind_dn"`
	BindPassword      string           `json:"bind_password"`
	BaseDN            string           `json:"base_dn"`
	UserBaseDN        string           `json:"user_base_dn"`
	GroupBaseDN       string           `json:"group_base_dn"`
	UserFilter        string           `json:"user_filter"`
	GroupFilter       string           `json:"group_filter"`
	MemberAttribute   string           `json:"member_attribute"`
	PageSize          int              `json:"page_size"`
	SyncInterval      int              `json:"sync_interval"` // minutes, 0=disabled
	SyncEnabled       bool             `json:"sync_enabled"`
	DeprovisionAction string           `json:"deprovision_action"` // "disable" or "delete"
	DirectoryType     string           `json:"directory_type"`     // "active_directory" or "openldap"
	AttributeMapping  AttributeMapping `json:"attribute_mapping"`

	// FollowReferrals enables chasing LDAP continuation references returned by a
	// search. It is opt-in because chasing one means opening a connection to a
	// host named by the directory server rather than by this configuration: a
	// forest that is misconfigured — or a directory an attacker can write a
	// referral into — can point the sync at an arbitrary address. Off, a search
	// spanning multiple naming contexts silently returns only the local slice.
	FollowReferrals bool `json:"follow_referrals"`
	// ReferralHopLimit bounds how deep referrals are chased. 0 uses
	// defaultReferralHopLimit. A referred server can itself return referrals, so
	// without a bound a cycle would loop until the sync times out.
	ReferralHopLimit int `json:"referral_hop_limit"`
}

// AzureADConfig holds Azure AD / Entra ID connection and sync configuration
type AzureADConfig struct {
	TenantID          string           `json:"tenant_id"`
	ClientID          string           `json:"client_id"`
	ClientSecret      string           `json:"client_secret"`
	UserFilter        string           `json:"user_filter"`   // OData $filter for /users
	GroupFilter       string           `json:"group_filter"`  // OData $filter for /groups
	SyncInterval      int              `json:"sync_interval"` // minutes
	SyncEnabled       bool             `json:"sync_enabled"`
	DeprovisionAction string           `json:"deprovision_action"` // "disable" or "delete"
	AttributeMapping  AttributeMapping `json:"attribute_mapping"`
}

// DirectoryConnector is the interface all directory connectors must implement
type DirectoryConnector interface {
	TestConnection(ctx context.Context) error
	SearchUsers(ctx context.Context) ([]UserRecord, error)
	SearchGroups(ctx context.Context) ([]GroupRecord, error)
}

// HRISConfig holds the connection + sync configuration for an HR source of
// truth (BambooHR today; the same shape covers Workday/SuccessFactors REST
// APIs). An HRIS is modeled as a directory-connector type: it lands users into
// the same users table and drives joiner/mover/leaver.
type HRISConfig struct {
	// Provider selects the HRIS dialect. Currently "bamboohr".
	Provider string `json:"provider"`
	// BaseURL overrides the provider's default API root (for Workday tenants or
	// testing). For BambooHR the default is https://api.bamboohr.com/api/gateway.php/<subdomain>.
	BaseURL string `json:"base_url"`
	// Subdomain is the BambooHR company subdomain (the <subdomain> above).
	Subdomain string `json:"subdomain"`
	// APIKey authenticates to the HRIS (BambooHR: sent as HTTP Basic username).
	APIKey string `json:"api_key"`
	// SyncInterval in minutes (0 = manual only); SyncEnabled gates the scheduler.
	SyncInterval int  `json:"sync_interval"`
	SyncEnabled  bool `json:"sync_enabled"`
	// DeprovisionAction on a leaver: "disable" (default) or "delete".
	DeprovisionAction string `json:"deprovision_action"`
	// UsernameField chooses which HR field becomes the OpenIDX username:
	// "email" (default) or "employee_number".
	UsernameField string `json:"username_field"`
}

// AttributeMapping maps LDAP attributes to OpenIDX user fields
type AttributeMapping struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DisplayName string `json:"display_name"`
	GroupName   string `json:"group_name"`
}

// UserRecord represents a user extracted from a directory
type UserRecord struct {
	DN          string
	ExternalID  string // Azure AD objectId or other external identifier
	Username    string
	Email       string
	FirstName   string
	LastName    string
	DisplayName string

	// HR/JML attributes. Populated by an HRIS connector (BambooHR/Workday/...);
	// left zero by LDAP/Azure connectors. These drive joiner/mover/leaver and
	// feed the outbound-SCIM enterprise extension + org chart.
	EmployeeNumber   string
	JobTitle         string
	Department       string
	ManagerExternal  string // manager's external HR id (resolved to manager_id at sync)
	HireDate         string // ISO-8601 (YYYY-MM-DD) or ""
	TerminationDate  string // ISO-8601 or ""
	EmploymentStatus string // active | terminated | on_leave | pending
}

// GroupRecord represents a group extracted from LDAP
type GroupRecord struct {
	DN          string
	Name        string
	Description string
	MemberDNs   []string
}

// SyncResult holds the results of a directory sync operation
type SyncResult struct {
	UsersAdded    int           `json:"users_added"`
	UsersUpdated  int           `json:"users_updated"`
	UsersDisabled int           `json:"users_disabled"`
	GroupsAdded   int           `json:"groups_added"`
	GroupsUpdated int           `json:"groups_updated"`
	GroupsDeleted int           `json:"groups_deleted"`
	Errors        []string      `json:"errors,omitempty"`
	Duration      time.Duration `json:"duration_ms"`
}

// SyncLog represents a sync log entry from the database
type SyncLog struct {
	ID            string     `json:"id"`
	DirectoryID   string     `json:"directory_id"`
	SyncType      string     `json:"sync_type"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	UsersAdded    int        `json:"users_added"`
	UsersUpdated  int        `json:"users_updated"`
	UsersDisabled int        `json:"users_disabled"`
	GroupsAdded   int        `json:"groups_added"`
	GroupsUpdated int        `json:"groups_updated"`
	GroupsDeleted int        `json:"groups_deleted"`
	ErrorMessage  *string    `json:"error_message,omitempty"`
}

// SyncState represents the current sync state for a directory
type SyncState struct {
	DirectoryID         string     `json:"directory_id"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty"`
	LastUSNChanged      *int64     `json:"last_usn_changed,omitempty"`
	LastModifyTimestamp *string    `json:"last_modify_timestamp,omitempty"`
	LastDeltaLink       *string    `json:"last_delta_link,omitempty"` // Azure AD delta query link
	UsersSynced         int        `json:"users_synced"`
	GroupsSynced        int        `json:"groups_synced"`
	ErrorsCount         int        `json:"errors_count"`
	SyncDurationMs      *int       `json:"sync_duration_ms,omitempty"`
}
