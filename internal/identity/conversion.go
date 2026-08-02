// Package identity provides user model conversion between database schema and SCIM models
package identity

import (
	"strconv"
	"time"
)

// UserDB represents a user as stored in the database with flat fields
// This matches the actual PostgreSQL schema and is used for SQL scanning
type UserDB struct {
	ID                 string     `json:"id" db:"id"`
	Username           string     `json:"username" db:"username"`
	Email              string     `json:"email" db:"email"`
	FirstName          string     `json:"first_name" db:"first_name"`
	LastName           string     `json:"last_name" db:"last_name"`
	PasswordHash       *string    `json:"-" db:"password_hash"` // Never expose
	Enabled            bool       `json:"enabled" db:"enabled"`
	EmailVerified      bool       `json:"email_verified" db:"email_verified"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	PasswordChangedAt  *time.Time `json:"password_changed_at,omitempty" db:"password_changed_at"`
	PasswordMustChange bool       `json:"password_must_change" db:"password_must_change"`
	FailedLoginCount   int        `json:"failed_login_count" db:"failed_login_count"`
	LastFailedLoginAt  *time.Time `json:"last_failed_login_at,omitempty" db:"last_failed_login_at"`
	LockedUntil        *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	Source             *string    `json:"source,omitempty" db:"source"`
	DirectoryID        *string    `json:"directory_id,omitempty" db:"directory_id"`
	LdapDN             *string    `json:"ldap_dn,omitempty" db:"ldap_dn"`
	OrganizationID     *string    `json:"organization_id,omitempty" db:"org_id"`
}

// ToUser converts UserDB to SCIM-compatible User model
func (u *UserDB) ToUser() User {
	user := User{
		ID:                 u.ID,
		UserName:           u.Username,
		Enabled:            u.Enabled,
		EmailVerified:      u.EmailVerified,
		Active:             u.Enabled, // SCIM uses Active for enabled status
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
		LastLoginAt:        u.LastLoginAt,
		PasswordChangedAt:  u.PasswordChangedAt,
		PasswordMustChange: u.PasswordMustChange,
		FailedLoginCount:   u.FailedLoginCount,
		LastFailedLoginAt:  u.LastFailedLoginAt,
		LockedUntil:        u.LockedUntil,
		Source:             u.Source,
		DirectoryID:        u.DirectoryID,
		LdapDN:             u.LdapDN,
	}

	// Set OrganizationID if present
	if u.OrganizationID != nil {
		user.OrganizationID = u.OrganizationID
	}

	// Convert flat name to SCIM Name structure
	if u.FirstName != "" || u.LastName != "" {
		user.Name = &Name{}
		if u.FirstName != "" {
			user.Name.GivenName = &u.FirstName
		}
		if u.LastName != "" {
			user.Name.FamilyName = &u.LastName
		}
	}

	// Convert flat email to SCIM Emails array.
	//
	// The address is typed "work" rather than left untyped. `users` holds one
	// address, so this is the account's only email and there is nothing to
	// distinguish it from — but the type matters on the way back in: Entra ID's
	// default attribute mapping updates an address with the PATCH path
	// `emails[type eq "work"].value`, and Okta's profile mapping does the same.
	// An untyped address matches neither filter, so the update would be
	// rejected as noTarget. Emitting the type we accept keeps GET and PATCH
	// describing the same resource.
	if u.Email != "" {
		primary := true
		emailType := "work"
		user.Emails = []Email{{
			Value:   u.Email,
			Type:    &emailType,
			Primary: &primary,
		}}
	}

	return user
}

// FromUser converts SCIM User to UserDB for database operations.
//
// SCIM 2.0 uses `active`, while the internal DB column is `enabled`. The
// User struct carries both fields independently; honor either one so SCIM
// clients (and the integration suite) that send `{"active": true}` don't
// silently create a disabled user that every later /users/:id lookup
// 404s on (handlers query `WHERE enabled = true`).
func FromUser(user User) UserDB {
	enabled := user.Enabled || user.Active

	dbUser := UserDB{
		ID:                 user.ID,
		Username:           user.UserName,
		Enabled:            enabled,
		EmailVerified:      user.EmailVerified,
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
		LastLoginAt:        user.LastLoginAt,
		PasswordChangedAt:  user.PasswordChangedAt,
		PasswordMustChange: user.PasswordMustChange,
		FailedLoginCount:   user.FailedLoginCount,
		LastFailedLoginAt:  user.LastFailedLoginAt,
		LockedUntil:        user.LockedUntil,
		Source:             user.Source,
		DirectoryID:        user.DirectoryID,
		LdapDN:             user.LdapDN,
	}

	// Extract OrganizationID if present
	if user.OrganizationID != nil {
		dbUser.OrganizationID = user.OrganizationID
	}

	// Extract name from SCIM structure
	if user.Name != nil {
		if user.Name.GivenName != nil {
			dbUser.FirstName = *user.Name.GivenName
		}
		if user.Name.FamilyName != nil {
			dbUser.LastName = *user.Name.FamilyName
		}
	}

	// Extract primary email from SCIM Emails array
	if len(user.Emails) > 0 {
		// Look for primary email
		for _, email := range user.Emails {
			if email.Primary != nil && *email.Primary {
				dbUser.Email = email.Value
				break
			}
		}
		// If no primary marked, use first email
		if dbUser.Email == "" {
			dbUser.Email = user.Emails[0].Value
		}
	}

	return dbUser
}

// Getter methods for UserDB to maintain compatibility

func (u *UserDB) GetUsername() string {
	return u.Username
}

func (u *UserDB) GetEmail() string {
	return u.Email
}

func (u *UserDB) GetFirstName() string {
	return u.FirstName
}

func (u *UserDB) GetLastName() string {
	return u.LastName
}

// GroupDB represents a group with flat database-compatible fields
type GroupDB struct {
	ID              string    `db:"id"`
	DisplayName     string    `db:"display_name"`
	Description     *string   `db:"description"`
	ParentID        *string   `db:"parent_id"`
	OrganizationID  *string   `db:"organization_id"`
	AllowSelfJoin   bool      `db:"allow_self_join"`
	RequireApproval bool      `db:"require_approval"`
	MaxMembers      *int      `db:"max_members"`
	MemberCount     int       `db:"member_count"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// ToGroup converts GroupDB to SCIM Group
func (g *GroupDB) ToGroup() Group {
	group := Group{
		ID:          g.ID,
		DisplayName: g.DisplayName,
		Members:     []Member{}, // Would need separate query for members
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}

	// Map optional fields
	if g.OrganizationID != nil {
		group.OrganizationID = g.OrganizationID
	}
	if g.Description != nil || g.ParentID != nil {
		group.Attributes = make(map[string]string)
		if g.Description != nil {
			group.Attributes["description"] = *g.Description
		}
		if g.ParentID != nil {
			group.Attributes["parentId"] = *g.ParentID
		}
	}

	return group
}

// FromGroup converts SCIM Group to GroupDB
func FromGroup(group Group) GroupDB {
	dbGroup := GroupDB{
		ID:          group.ID,
		DisplayName: group.DisplayName,
		CreatedAt:   group.CreatedAt,
		UpdatedAt:   group.UpdatedAt,
	}

	// Extract optional fields from attributes
	if group.Attributes != nil {
		if desc, ok := group.Attributes["description"]; ok {
			dbGroup.Description = &desc
		}
		if parentID, ok := group.Attributes["parentId"]; ok {
			dbGroup.ParentID = &parentID
		}
		// Extract boolean fields
		if allowSelfJoin, ok := group.Attributes["allowSelfJoin"]; ok {
			dbGroup.AllowSelfJoin = allowSelfJoin == "true"
		}
		if requireApproval, ok := group.Attributes["requireApproval"]; ok {
			dbGroup.RequireApproval = requireApproval == "true"
		}
		// Extract max members
		if maxMembersStr, ok := group.Attributes["maxMembers"]; ok {
			if maxMembers, err := strconv.Atoi(maxMembersStr); err == nil {
				dbGroup.MaxMembers = &maxMembers
			}
		}
	}

	if group.OrganizationID != nil {
		dbGroup.OrganizationID = group.OrganizationID
	}

	return dbGroup
}

// GetEmail returns the primary email address from a SCIM User
// This is a helper for backward compatibility with code that expects user.Email
func GetEmail(user User) string {
	if len(user.Emails) > 0 {
		// Return primary email if marked
		for _, email := range user.Emails {
			if email.Primary != nil && *email.Primary {
				return email.Value
			}
		}
		// Otherwise return first email
		return user.Emails[0].Value
	}
	return ""
}

// GetUsername returns the username from a SCIM User
// This is a helper for backward compatibility with code that expects user.Username
func GetUsername(user User) string {
	return user.UserName
}

// GetFirstName returns the first name from a SCIM User
func GetFirstName(user User) string {
	if user.Name != nil && user.Name.GivenName != nil {
		return *user.Name.GivenName
	}
	return ""
}

// GetLastName returns the last name from a SCIM User
func GetLastName(user User) string {
	if user.Name != nil && user.Name.FamilyName != nil {
		return *user.Name.FamilyName
	}
	return ""
}
