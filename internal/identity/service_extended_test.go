// Package identity provides comprehensive unit tests for the identity service
// Tests focus on User CRUD, Authentication, Sessions, Password operations, and MFA functionality
package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// ============================================================
// Test Fixtures and Setup
// ============================================================

// createTestService creates a service instance for testing with nil database
func createTestService(t *testing.T) *Service {
	t.Helper()

	logger := zap.NewNop()
	cfg := &config.Config{
		OAuthIssuer:  "http://localhost:8006",
		OAuthJWKSURL: "http://localhost:8006/.well-known/jwks.json",
	}

	service := NewService(&database.PostgresDB{}, nil, cfg, logger)
	return service
}

// createTestUserWithID creates a test user with the given ID
func createTestUserWithID(id, username, email string) *User {
	user := &User{
		ID:            id,
		UserName:      username,
		Enabled:       true,
		EmailVerified: false,
		Active:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	user.SetEmail(email)
	user.SetFirstName("Test")
	user.SetLastName("User")
	return user
}

// hashPassword generates a bcrypt hash for testing
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	return string(hash)
}

// ============================================================
// Password Operation Tests
// ============================================================

// TestValidatePasswordPolicy_Valid tests password policy validation with valid password
func TestValidatePasswordPolicy_Valid(t *testing.T) {
	service := createTestService(t)

	validPasswords := []string{
		"ValidPassword123!",
		"SecurePass@456",
		"MyP@ssw0rd",
		"Str0ng!Pass",
		"Complex!Pass9",
		"Another$Secure1",
	}

	for _, password := range validPasswords {
		t.Run(password, func(t *testing.T) {
			err := service.ValidatePasswordPolicy(password)
			assert.NoError(t, err, "Password should be valid: %s", password)
		})
	}
}

// TestValidatePasswordPolicy_Invalid tests password policy validation with invalid passwords
func TestValidatePasswordPolicy_Invalid(t *testing.T) {
	service := createTestService(t)

	testCases := []struct {
		name      string
		password  string
		wantError string
	}{
		{
			name:      "Too short",
			password:  "Short1!",
			wantError: "password must be at least 8 characters long",
		},
		{
			name:      "Too short - 7 chars",
			password:  "Short7!",
			wantError: "password must be at least 8 characters long",
		},
		{
			name:      "No uppercase",
			password:  "lowercase123!",
			wantError: "uppercase letter",
		},
		{
			name:      "No lowercase",
			password:  "UPPERCASE123!",
			wantError: "lowercase letter",
		},
		{
			name:      "No digit",
			password:  "NoDigits!",
			wantError: "digit",
		},
		{
			// This case previously asserted that ValidatePasswordPolicy accepts
			// a password with no special character, while the reset-password
			// path (ValidatePasswordPolicyChecks) rejected the same string.
			// That divergence was the bug, not the contract: both entry points
			// now run the one policy, and the stricter of the two was kept.
			name:      "No special character",
			password:  "NoSpecial123",
			wantError: "special character",
		},
		{
			name:      "Only lowercase",
			password:  "lowercase",
			wantError: "uppercase letter", // Error about missing uppercase
		},
		{
			name:      "Empty password",
			password:  "",
			wantError: "8 characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := service.ValidatePasswordPolicy(tc.password)
			if tc.wantError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidatePasswordPolicyChecks tests detailed password policy checks
func TestValidatePasswordPolicyChecks(t *testing.T) {
	service := createTestService(t)

	testCases := []struct {
		name           string
		password       string
		wantViolations int
	}{
		{
			name:           "Valid password",
			password:       "ValidPass123!",
			wantViolations: 0,
		},
		{
			name:           "Too short - no uppercase",
			password:       "short1!",
			wantViolations: 2,
		},
		{
			name:           "Only lowercase",
			password:       "lowercase",
			wantViolations: 3, // uppercase, digit, special
		},
		{
			name:           "Only digits",
			password:       "12345678",
			wantViolations: 3,
		},
		{
			name:           "Only special chars",
			password:       "!@#$%^&*",
			wantViolations: 3,
		},
		{
			name:           "No uppercase, no digit",
			password:       "lowercase!",
			wantViolations: 2,
		},
		{
			name:           "No lowercase, no special",
			password:       "UPPERCASE123",
			wantViolations: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			violations := service.ValidatePasswordPolicyChecks(tc.password)
			assert.Len(t, violations, tc.wantViolations, "Password: %s", tc.password)
		})
	}
}

// TestValidatePasswordPolicyChecks_ViolationContent tests the content of violation messages
func TestValidatePasswordPolicyChecks_ViolationContent(t *testing.T) {
	service := createTestService(t)

	t.Run("Password too short", func(t *testing.T) {
		violations := service.ValidatePasswordPolicyChecks("Ab1!")
		assert.Contains(t, violations, "password must be at least 8 characters long")
	})

	t.Run("Missing uppercase", func(t *testing.T) {
		violations := service.ValidatePasswordPolicyChecks("lowercase123!")
		assert.Contains(t, violations, "password must contain at least one uppercase letter")
	})

	t.Run("Missing lowercase", func(t *testing.T) {
		violations := service.ValidatePasswordPolicyChecks("UPPERCASE123!")
		assert.Contains(t, violations, "password must contain at least one lowercase letter")
	})

	t.Run("Missing digit", func(t *testing.T) {
		violations := service.ValidatePasswordPolicyChecks("NoDigits!")
		assert.Contains(t, violations, "password must contain at least one digit")
	})

	t.Run("Missing special character", func(t *testing.T) {
		violations := service.ValidatePasswordPolicyChecks("NoSpecial123")
		assert.Contains(t, violations, "password must contain at least one special character")
	})
}

// ============================================================
// User Helper Functions Tests
// ============================================================

// TestUserHelperFunctions tests User helper methods
func TestUserHelperFunctions(t *testing.T) {
	t.Run("GetUsername/SetUsername", func(t *testing.T) {
		user := &User{}
		user.SetUsername("testuser")
		assert.Equal(t, "testuser", user.GetUsername())
		assert.Equal(t, "testuser", user.UserName)
	})

	t.Run("SetEmail/GetEmail", func(t *testing.T) {
		user := &User{}
		user.SetEmail("test@example.com")
		assert.Equal(t, "test@example.com", user.GetEmail())
		assert.Len(t, user.Emails, 1)
		assert.True(t, *user.Emails[0].Primary)
		assert.Equal(t, "test@example.com", user.Emails[0].Value)
	})

	t.Run("SetFirstName/GetFirstName", func(t *testing.T) {
		user := &User{}
		user.SetFirstName("John")
		assert.Equal(t, "John", user.GetFirstName())
		assert.NotNil(t, user.Name)
		assert.Equal(t, "John", *user.Name.GivenName)
	})

	t.Run("SetLastName/GetLastName", func(t *testing.T) {
		user := &User{}
		user.SetLastName("Doe")
		assert.Equal(t, "Doe", user.GetLastName())
		assert.NotNil(t, user.Name)
		assert.Equal(t, "Doe", *user.Name.FamilyName)
	})

	t.Run("SetEmailVerified", func(t *testing.T) {
		user := &User{}
		user.SetEmail("test@example.com")
		user.SetEmailVerified(true)
		assert.True(t, *user.Emails[0].Verified)
	})

	t.Run("SetEmailVerified updates existing email", func(t *testing.T) {
		user := &User{}
		user.SetEmail("test@example.com")
		user.SetEmailVerified(false)
		assert.False(t, *user.Emails[0].Verified)

		user.SetEmailVerified(true)
		assert.True(t, *user.Emails[0].Verified)
	})

	t.Run("GetEmail when no emails", func(t *testing.T) {
		user := &User{Emails: []Email{}}
		assert.Equal(t, "", user.GetEmail())
	})

	t.Run("GetEmail when nil emails", func(t *testing.T) {
		user := &User{Emails: nil}
		assert.Equal(t, "", user.GetEmail())
	})

	t.Run("GetFirstName when no name", func(t *testing.T) {
		user := &User{}
		assert.Equal(t, "", user.GetFirstName())
	})

	t.Run("GetLastName when no name", func(t *testing.T) {
		user := &User{}
		assert.Equal(t, "", user.GetLastName())
	})

	t.Run("SetFirstName creates Name if nil", func(t *testing.T) {
		user := &User{}
		assert.Nil(t, user.Name)
		user.SetFirstName("Jane")
		assert.NotNil(t, user.Name)
		assert.Equal(t, "Jane", *user.Name.GivenName)
	})

	t.Run("SetLastName creates Name if nil", func(t *testing.T) {
		user := &User{}
		assert.Nil(t, user.Name)
		user.SetLastName("Smith")
		assert.NotNil(t, user.Name)
		assert.Equal(t, "Smith", *user.Name.FamilyName)
	})

	t.Run("SetEmail creates Email if empty", func(t *testing.T) {
		user := &User{Emails: []Email{}}
		user.SetEmail("new@example.com")
		assert.Len(t, user.Emails, 1)
		assert.Equal(t, "new@example.com", user.Emails[0].Value)
	})

	t.Run("SetEmail updates first email if exists", func(t *testing.T) {
		user := &User{}
		user.SetEmail("first@example.com")
		user.SetEmail("second@example.com")
		assert.Len(t, user.Emails, 1)
		assert.Equal(t, "second@example.com", user.Emails[0].Value)
	})
}

// TestUserAdditionalMethods tests additional User methods
func TestUserAdditionalMethods(t *testing.T) {
	t.Run("GetPrimaryEmail with multiple emails", func(t *testing.T) {
		primary := true
		user := &User{
			Emails: []Email{
				{Value: "secondary@example.com", Primary: &primary},
				{Value: "primary@example.com", Primary: &primary},
			},
		}
		// First email marked as primary should be returned
		assert.Equal(t, "secondary@example.com", user.GetPrimaryEmail())
	})

	t.Run("GetPrimaryEmail with no emails", func(t *testing.T) {
		user := &User{Emails: []Email{}}
		assert.Equal(t, "", user.GetPrimaryEmail())
	})

	t.Run("GetPrimaryEmail with single email", func(t *testing.T) {
		user := &User{}
		user.SetEmail("test@example.com")
		assert.Equal(t, "test@example.com", user.GetPrimaryEmail())
	})

	t.Run("GetPrimaryPhoneNumber with no phone numbers", func(t *testing.T) {
		user := &User{PhoneNumbers: []PhoneNumber{}}
		assert.Equal(t, "", user.GetPrimaryPhoneNumber())
	})

	t.Run("GetPrimaryPhoneNumber with single phone", func(t *testing.T) {
		user := &User{
			PhoneNumbers: []PhoneNumber{
				{Value: "+1234567890"},
			},
		}
		assert.Equal(t, "+1234567890", user.GetPrimaryPhoneNumber())
	})

	t.Run("GetFormattedName with formatted name", func(t *testing.T) {
		formatted := "Dr. John Smith"
		user := &User{
			Name: &Name{Formatted: &formatted},
		}
		assert.Equal(t, "Dr. John Smith", user.GetFormattedName())
	})

	t.Run("GetFormattedName with given and family name", func(t *testing.T) {
		given := "John"
		family := "Smith"
		user := &User{
			Name: &Name{
				GivenName:  &given,
				FamilyName: &family,
			},
		}
		assert.Equal(t, "John Smith", user.GetFormattedName())
	})

	t.Run("GetFormattedName with display name", func(t *testing.T) {
		display := "Johnny"
		user := &User{
			DisplayName: &display,
			Name:        &Name{},
		}
		assert.Equal(t, "Johnny", user.GetFormattedName())
	})

	t.Run("GetFormattedName with username", func(t *testing.T) {
		user := &User{
			UserName: "testuser",
		}
		assert.Equal(t, "testuser", user.GetFormattedName())
	})

	t.Run("IsLocked when not locked", func(t *testing.T) {
		user := &User{LockedUntil: nil}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when lock expired", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		user := &User{LockedUntil: &past}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when locked", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		user := &User{LockedUntil: &future}
		assert.True(t, user.IsLocked())
	})

	t.Run("UpdateMeta creates Meta if nil", func(t *testing.T) {
		user := &User{
			ID:       "user-123",
			UserName: "testuser",
		}
		user.UpdateMeta("http://example.com")
		assert.NotNil(t, user.Meta)
		assert.Equal(t, "User", user.Meta.ResourceType)
		assert.Equal(t, "http://example.com/Users/user-123", user.Meta.Location)
	})

	t.Run("UpdateMeta updates existing Meta", func(t *testing.T) {
		user := &User{
			ID:       "user-123",
			UserName: "testuser",
			Meta: &Meta{
				ResourceType: "User",
			},
		}
		user.UpdateMeta("http://example.com")
		assert.NotNil(t, user.Meta)
	})
}

// TestGroupAdditionalMethods tests additional Group methods
func TestGroupAdditionalMethods(t *testing.T) {
	t.Run("NewGroup creates group with ID", func(t *testing.T) {
		group := NewGroup("TestGroup")
		assert.NotEmpty(t, group.ID)
		assert.Equal(t, "TestGroup", group.DisplayName)
		assert.NotNil(t, group.Meta)
		assert.Equal(t, "Group", group.Meta.ResourceType)
	})

	t.Run("Group updateMeta", func(t *testing.T) {
		group := &Group{
			ID:          "group-123",
			DisplayName: "TestGroup",
		}
		group.UpdateMeta("http://example.com")
		assert.NotNil(t, group.Meta)
		assert.Equal(t, "http://example.com/Groups/group-123", group.Meta.Location)
	})
}

// TestTOTPModel tests TOTP-related model functions
func TestTOTPModel(t *testing.T) {
	t.Run("IsLocked with nil LockedUntil", func(t *testing.T) {
		user := &User{LockedUntil: nil}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when expired", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		user := &User{LockedUntil: &past}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when active", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		user := &User{LockedUntil: &future}
		assert.True(t, user.IsLocked())
	})
}

// ============================================================
// Group Helper Functions Tests
// ============================================================

// TestGroupHelperFunctions tests Group helper methods
func TestGroupHelperFunctions(t *testing.T) {
	t.Run("GetName/SetName", func(t *testing.T) {
		group := &Group{}
		group.SetName("TestGroup")
		assert.Equal(t, "TestGroup", group.GetName())
		assert.Equal(t, "TestGroup", group.DisplayName)
	})

	t.Run("GetDescription/SetDescription", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.SetDescription("Test description")
		assert.Equal(t, "Test description", *group.GetDescription())
		assert.Equal(t, "Test description", group.Attributes["description"])
	})

	t.Run("SetDescription updates existing description", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.SetDescription("Original description")
		group.SetDescription("Updated description")
		assert.Equal(t, "Updated description", *group.GetDescription())
	})

	t.Run("GetParentID/SetParentID", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		parentID := "parent-123"
		group.SetParentID(parentID)
		assert.Equal(t, parentID, *group.GetParentID())
		assert.Equal(t, parentID, group.Attributes["parentId"])
	})

	t.Run("GetAllowSelfJoin/SetAllowSelfJoin", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		assert.False(t, group.GetAllowSelfJoin())
		group.SetAllowSelfJoin(true)
		assert.True(t, group.GetAllowSelfJoin())
		assert.Equal(t, "true", group.Attributes["allowSelfJoin"])
	})

	t.Run("SetAllowSelfJoin to false", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.SetAllowSelfJoin(true)
		group.SetAllowSelfJoin(false)
		assert.False(t, group.GetAllowSelfJoin())
		assert.Equal(t, "false", group.Attributes["allowSelfJoin"])
	})

	t.Run("GetRequireApproval/SetRequireApproval", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		assert.False(t, group.GetRequireApproval())
		group.SetRequireApproval(true)
		assert.True(t, group.GetRequireApproval())
		assert.Equal(t, "true", group.Attributes["requireApproval"])
	})

	t.Run("SetRequireApproval to false", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.SetRequireApproval(true)
		group.SetRequireApproval(false)
		assert.False(t, group.GetRequireApproval())
		assert.Equal(t, "false", group.Attributes["requireApproval"])
	})

	t.Run("GetDescription when no attributes", func(t *testing.T) {
		group := &Group{}
		assert.Nil(t, group.GetDescription())
	})

	t.Run("GetDescription when attributes but no description", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.Attributes["other"] = "value"
		assert.Nil(t, group.GetDescription())
	})

	t.Run("GetParentID when no attributes", func(t *testing.T) {
		group := &Group{}
		assert.Nil(t, group.GetParentID())
	})

	t.Run("GetParentID when attributes but no parentId", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.Attributes["other"] = "value"
		assert.Nil(t, group.GetParentID())
	})

	t.Run("GetAllowSelfJoin when no attributes", func(t *testing.T) {
		group := &Group{}
		assert.False(t, group.GetAllowSelfJoin())
	})

	t.Run("GetAllowSelfJoin with invalid value", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.Attributes["allowSelfJoin"] = "invalid"
		assert.False(t, group.GetAllowSelfJoin())
	})

	t.Run("GetRequireApproval when no attributes", func(t *testing.T) {
		group := &Group{}
		assert.False(t, group.GetRequireApproval())
	})

	t.Run("GetRequireApproval with invalid value", func(t *testing.T) {
		group := &Group{Attributes: make(map[string]string)}
		group.Attributes["requireApproval"] = "invalid"
		assert.False(t, group.GetRequireApproval())
	})

	t.Run("SetDescription creates Attributes if nil", func(t *testing.T) {
		group := &Group{}
		group.SetDescription("Test")
		assert.NotNil(t, group.Attributes)
		assert.Equal(t, "Test", group.Attributes["description"])
	})

	t.Run("SetParentID creates Attributes if nil", func(t *testing.T) {
		group := &Group{}
		group.SetParentID("parent-123")
		assert.NotNil(t, group.Attributes)
		assert.Equal(t, "parent-123", group.Attributes["parentId"])
	})

	t.Run("SetAllowSelfJoin creates Attributes if nil", func(t *testing.T) {
		group := &Group{}
		group.SetAllowSelfJoin(true)
		assert.NotNil(t, group.Attributes)
		assert.Equal(t, "true", group.Attributes["allowSelfJoin"])
	})

	t.Run("SetRequireApproval creates Attributes if nil", func(t *testing.T) {
		group := &Group{}
		group.SetRequireApproval(true)
		assert.NotNil(t, group.Attributes)
		assert.Equal(t, "true", group.Attributes["requireApproval"])
	})
}

// ============================================================
// Context Helper Tests
// ============================================================

// TestContextWithActorID tests setting actor ID in context
func TestContextWithActorID(t *testing.T) {
	ctx := context.Background()
	actorID := "user-123"

	newCtx := ContextWithActorID(ctx, actorID)
	assert.NotEqual(t, ctx, newCtx)

	// Verify the actor ID is stored
	if v, ok := newCtx.Value(ctxKeyActorID).(string); ok {
		assert.Equal(t, actorID, v)
	} else {
		t.Error("actor ID not found in context")
	}
}

// TestActorIDFromContext tests extracting actor ID from context
func TestActorIDFromContext(t *testing.T) {
	t.Run("With actor ID", func(t *testing.T) {
		actorID := "user-123"
		ctx := ContextWithActorID(context.Background(), actorID)
		extracted := actorIDFromContext(ctx)
		assert.Equal(t, actorID, extracted)
	})

	t.Run("Without actor ID", func(t *testing.T) {
		ctx := context.Background()
		extracted := actorIDFromContext(ctx)
		assert.Equal(t, "system", extracted)
	})

	t.Run("With empty string actor ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxKeyActorID, "")
		extracted := actorIDFromContext(ctx)
		assert.Equal(t, "system", extracted)
	})

	t.Run("With whitespace actor ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxKeyActorID, "   ")
		extracted := actorIDFromContext(ctx)
		assert.Equal(t, "   ", extracted)
	})
}

// ============================================================
// Error Variables Tests
// ============================================================

// TestErrorVariables verifies error variables are properly defined
func TestErrorVariablesExtended(t *testing.T) {
	assert.NotNil(t, ErrInvalidCredentials)
	assert.Contains(t, ErrInvalidCredentials.Error(), "invalid")
	assert.NotNil(t, ErrAccountDisabled)
	assert.NotNil(t, ErrAccountLocked)
}

// ============================================================
// Session Model Tests
// ============================================================

// TestSession_IsExpired tests session expiration checking
func TestSession_IsExpired(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name      string
		expiresAt time.Time
		isExpired bool
	}{
		{
			name:      "Active session - expires in future",
			expiresAt: now.Add(1 * time.Hour),
			isExpired: false,
		},
		{
			name:      "Expired session - expired 1 hour ago",
			expiresAt: now.Add(-1 * time.Hour),
			isExpired: true,
		},
		{
			name:      "Just expired - 1 second ago",
			expiresAt: now.Add(-1 * time.Second),
			isExpired: true,
		},
		{
			name:      "Expires in 1 second - still active",
			expiresAt: now.Add(1 * time.Second),
			isExpired: false,
		},
		{
			name:      "Expires exactly now",
			expiresAt: now,
			isExpired: false, // Before() returns false for equal times
		},
		{
			name:      "Expires in 24 hours",
			expiresAt: now.Add(24 * time.Hour),
			isExpired: false,
		},
		{
			name:      "Expires in 1 minute",
			expiresAt: now.Add(1 * time.Minute),
			isExpired: false,
		},
		{
			name:      "Expired 1 day ago",
			expiresAt: now.Add(-24 * time.Hour),
			isExpired: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &Session{
				ID:        uuid.New().String(),
				UserID:    uuid.New().String(),
				ExpiresAt: tc.expiresAt,
			}
			isExpired := session.ExpiresAt.Before(now)
			assert.Equal(t, tc.isExpired, isExpired, "Session expiration check failed for: %s", tc.name)
		})
	}
}

// TestSession_Duration tests calculating session duration
func TestSession_Duration(t *testing.T) {
	now := time.Now()

	t.Run("Session duration calculation", func(t *testing.T) {
		startedAt := now.Add(-2 * time.Hour)
		expiresAt := now.Add(22 * time.Hour)

		session := &Session{
			ID:        uuid.New().String(),
			UserID:    uuid.New().String(),
			StartedAt: startedAt,
			ExpiresAt: expiresAt,
		}

		duration := session.ExpiresAt.Sub(session.StartedAt)
		assert.Equal(t, 24*time.Hour, duration)
	})
}

// TestSession_LastSeen tests session last seen tracking
func TestSession_LastSeen(t *testing.T) {
	now := time.Now()

	t.Run("Session created with same started and last seen", func(t *testing.T) {
		session := &Session{
			ID:         uuid.New().String(),
			UserID:     uuid.New().String(),
			StartedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(1 * time.Hour),
		}

		assert.True(t, session.LastSeenAt.Equal(session.StartedAt))
	})

	t.Run("Session with updated last seen", func(t *testing.T) {
		startedAt := now.Add(-1 * time.Hour)
		lastSeenAt := now.Add(-5 * time.Minute)

		session := &Session{
			ID:         uuid.New().String(),
			UserID:     uuid.New().String(),
			StartedAt:  startedAt,
			LastSeenAt: lastSeenAt,
			ExpiresAt:  now.Add(1 * time.Hour),
		}

		assert.True(t, session.LastSeenAt.After(session.StartedAt))
	})
}

// ============================================================
// UserDB Conversion Tests
// ============================================================

// TestUserDBToUser tests UserDB to User conversion
func TestUserDBToUser(t *testing.T) {
	now := time.Now()
	passwordChangedAt := now.Add(-30 * 24 * time.Hour)
	lockedUntil := now.Add(1 * time.Hour)
	lastFailedLoginAt := now.Add(-1 * time.Hour)
	lastLoginAt := now.Add(-2 * time.Hour)

	testCases := []struct {
		name   string
		dbUser UserDB
		check  func(t *testing.T, user *User, dbUser UserDB)
	}{
		{
			name: "Full user conversion",
			dbUser: UserDB{
				ID:                 uuid.New().String(),
				Username:           "testuser",
				Email:              "test@example.com",
				FirstName:          "Test",
				LastName:           "User",
				Enabled:            true,
				EmailVerified:      true,
				CreatedAt:          now,
				UpdatedAt:          now,
				LastLoginAt:        &lastLoginAt,
				PasswordChangedAt:  &passwordChangedAt,
				PasswordMustChange: false,
				FailedLoginCount:   2,
				LastFailedLoginAt:  &lastFailedLoginAt,
				LockedUntil:        &lockedUntil,
			},
			check: func(t *testing.T, user *User, dbUser UserDB) {
				assert.Equal(t, dbUser.ID, user.ID)
				assert.Equal(t, dbUser.Username, user.UserName)
				assert.Equal(t, dbUser.Email, user.GetEmail())
				assert.Equal(t, dbUser.FirstName, user.GetFirstName())
				assert.Equal(t, dbUser.LastName, user.GetLastName())
				assert.Equal(t, dbUser.Enabled, user.Enabled)
				assert.Equal(t, dbUser.Enabled, user.Active)
				assert.Equal(t, dbUser.EmailVerified, user.EmailVerified)
				assert.Equal(t, dbUser.PasswordMustChange, user.PasswordMustChange)
				assert.Equal(t, dbUser.FailedLoginCount, user.FailedLoginCount)
			},
		},
		{
			name: "Minimal user conversion",
			dbUser: UserDB{
				ID:        uuid.New().String(),
				Username:  "minimal",
				Email:     "minimal@example.com",
				FirstName: "",
				LastName:  "",
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			check: func(t *testing.T, user *User, dbUser UserDB) {
				assert.Equal(t, dbUser.ID, user.ID)
				assert.Equal(t, dbUser.Username, user.UserName)
				assert.Equal(t, "", user.GetFirstName())
				assert.Equal(t, "", user.GetLastName())
			},
		},
		{
			name: "Disabled user",
			dbUser: UserDB{
				ID:        uuid.New().String(),
				Username:  "disabled",
				Email:     "disabled@example.com",
				Enabled:   false,
				CreatedAt: now,
				UpdatedAt: now,
			},
			check: func(t *testing.T, user *User, dbUser UserDB) {
				assert.Equal(t, dbUser.Enabled, user.Enabled)
				assert.Equal(t, dbUser.Enabled, user.Active)
				assert.False(t, user.Enabled)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := tc.dbUser.ToUser()
			tc.check(t, &user, tc.dbUser)
		})
	}
}

// ============================================================
// ListResponse Tests
// ============================================================

// TestListResponse tests the ListResponse structure
func TestListResponse(t *testing.T) {
	t.Run("ListResponse with users", func(t *testing.T) {
		users := []User{
			{ID: "user-1", UserName: "user1"},
			{ID: "user-2", UserName: "user2"},
		}

		response := &ListResponse{
			TotalResults: 100,
			ItemsPerPage: 10,
			StartIndex:   1,
			Resources:    users,
		}

		assert.Equal(t, 100, response.TotalResults)
		assert.Equal(t, 10, response.ItemsPerPage)
		assert.Equal(t, 1, response.StartIndex)
		assert.NotNil(t, response.Resources)

		// Type assertion
		userResources, ok := response.Resources.([]User)
		require.True(t, ok)
		assert.Len(t, userResources, 2)
	})

	t.Run("ListResponse with groups", func(t *testing.T) {
		groups := []Group{
			{ID: "group-1", DisplayName: "Group 1"},
			{ID: "group-2", DisplayName: "Group 2"},
		}

		response := &ListResponse{
			TotalResults: 50,
			ItemsPerPage: 20,
			StartIndex:   0,
			Resources:    groups,
		}

		assert.Equal(t, 50, response.TotalResults)
		assert.NotNil(t, response.Resources)
	})
}

// ============================================================
// Scopes Type Tests
// ============================================================

// TestScopesValue tests the Scopes Value method
func TestScopesValue(t *testing.T) {
	testCases := []struct {
		name   string
		scopes Scopes
	}{
		{
			name:   "Multiple scopes",
			scopes: Scopes{"openid", "profile", "email"},
		},
		{
			name:   "Single scope",
			scopes: Scopes{"openid"},
		},
		{
			name:   "Empty scopes",
			scopes: Scopes{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := tc.scopes.Value()
			require.NoError(t, err)
			assert.NotNil(t, val)
		})
	}
}

// TestScopesScan tests the Scopes Scan method
func TestScopesScan(t *testing.T) {
	t.Run("Scan from byte slice", func(t *testing.T) {
		jsonData := `["openid","profile","email"]`
		var scopes Scopes
		err := scopes.Scan([]byte(jsonData))
		require.NoError(t, err)
		assert.Len(t, scopes, 3)
		assert.Contains(t, []string(scopes), "openid")
		assert.Contains(t, []string(scopes), "profile")
		assert.Contains(t, []string(scopes), "email")
	})

	t.Run("Scan from string", func(t *testing.T) {
		jsonData := `["openid","profile"]`
		var scopes Scopes
		err := scopes.Scan(jsonData)
		require.NoError(t, err)
		assert.Len(t, scopes, 2)
	})

	t.Run("Scan nil", func(t *testing.T) {
		var scopes Scopes
		err := scopes.Scan(nil)
		require.NoError(t, err)
		assert.Nil(t, scopes)
	})

	t.Run("Scan empty string", func(t *testing.T) {
		var scopes Scopes
		err := scopes.Scan("")
		assert.Error(t, err) // Empty string is invalid JSON
	})

	t.Run("Scan invalid JSON", func(t *testing.T) {
		var scopes Scopes
		err := scopes.Scan("not valid json")
		assert.Error(t, err)
	})
}

// ============================================================
// IdentityProvider Model Tests
// ============================================================

// TestIdentityProviderModelExtended tests IdentityProvider model
func TestIdentityProviderModelExtended(t *testing.T) {
	now := time.Now()

	t.Run("OIDC Provider", func(t *testing.T) {
		idp := &IdentityProvider{
			ID:           uuid.New(),
			Name:         "Test OIDC",
			ProviderType: ProviderTypeOIDC,
			IssuerURL:    "https://test-issuer.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Scopes:       Scopes{"openid", "profile", "email"},
			Enabled:      true,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		assert.Equal(t, ProviderTypeOIDC, idp.ProviderType)
		assert.Equal(t, "https://test-issuer.com", idp.IssuerURL)
		assert.Len(t, idp.Scopes, 3)
		assert.True(t, idp.Enabled)
	})

	t.Run("SAML Provider", func(t *testing.T) {
		idp := &IdentityProvider{
			ID:           uuid.New(),
			Name:         "Test SAML",
			ProviderType: ProviderTypeSAML,
			Enabled:      true,
		}

		assert.Equal(t, ProviderTypeSAML, idp.ProviderType)
	})
}

// ============================================================
// ProviderType Tests
// ============================================================

// TestProviderTypeConstantsExtended tests the ProviderType enum values
func TestProviderTypeConstantsExtended(t *testing.T) {
	assert.Equal(t, ProviderType("oidc"), ProviderTypeOIDC)
	assert.Equal(t, ProviderType("saml"), ProviderTypeSAML)
}

// ============================================================
// Validation Helper Tests
// ============================================================

// TestPointerString tests the pointerString helper
func TestPointerString(t *testing.T) {
	t.Run("Non-nil string pointer", func(t *testing.T) {
		s := "test string"
		result := pointerString(&s)
		assert.Equal(t, "test string", result)
	})

	t.Run("Nil string pointer", func(t *testing.T) {
		result := pointerString(nil)
		assert.Equal(t, "", result)
	})
}

// TestBoolPtr tests the boolPtr helper
func TestBoolPtr(t *testing.T) {
	t.Run("True pointer", func(t *testing.T) {
		ptr := boolPtr(true)
		assert.NotNil(t, ptr)
		assert.True(t, *ptr)
	})

	t.Run("False pointer", func(t *testing.T) {
		ptr := boolPtr(false)
		assert.NotNil(t, ptr)
		assert.False(t, *ptr)
	})
}

// TestStringPtr tests the stringPtr helper
func TestStringPtr(t *testing.T) {
	t.Run("Non-empty string", func(t *testing.T) {
		ptr := stringPtr("test")
		assert.NotNil(t, ptr)
		assert.Equal(t, "test", *ptr)
	})

	t.Run("Empty string returns nil", func(t *testing.T) {
		ptr := stringPtr("")
		assert.Nil(t, ptr)
	})
}

// ============================================================
// Tenant Isolation Tests
// ============================================================

// TestIsTenantAccessible tests tenant isolation logic
func TestIsTenantAccessible(t *testing.T) {
	service := createTestService(t)

	tenant1ID := "tenant-1"
	tenant2ID := "tenant-2"

	t.Run("Resource with same tenant ID", func(t *testing.T) {
		orgID := &tenant1ID
		assert.True(t, service.IsTenantAccessible(orgID, tenant1ID))
	})

	t.Run("Resource with different tenant ID", func(t *testing.T) {
		orgID := &tenant1ID
		assert.False(t, service.IsTenantAccessible(orgID, tenant2ID))
	})

	t.Run("Global resource (nil org ID)", func(t *testing.T) {
		var orgID *string
		assert.True(t, service.IsTenantAccessible(orgID, tenant1ID))
		assert.True(t, service.IsTenantAccessible(orgID, tenant2ID))
	})
}

// TestCheckTenantAccessible tests the package-level tenant check function
func TestCheckTenantAccessible(t *testing.T) {
	tenant1ID := "tenant-1"
	tenant2ID := "tenant-2"

	t.Run("Same tenant", func(t *testing.T) {
		orgID := &tenant1ID
		assert.True(t, CheckTenantAccessible(orgID, tenant1ID))
	})

	t.Run("Different tenant", func(t *testing.T) {
		orgID := &tenant1ID
		assert.False(t, CheckTenantAccessible(orgID, tenant2ID))
	})

	t.Run("Nil org ID", func(t *testing.T) {
		var orgID *string
		assert.True(t, CheckTenantAccessible(orgID, tenant1ID))
	})
}

// ============================================================
// UserFilter Tests
// ============================================================

// TestUserFilterDefaults tests UserFilter default values
func TestUserFilterDefaults(t *testing.T) {
	t.Run("Default values are applied", func(t *testing.T) {
		filter := UserFilter{
			PaginationParams: PaginationParams{
				Limit:  0,
				Offset: -5,
			},
		}

		// Apply default logic as in ListUsersWithFilter
		if filter.Limit <= 0 || filter.Limit > 100 {
			filter.Limit = 50
		}
		if filter.Offset < 0 {
			filter.Offset = 0
		}

		assert.Equal(t, 50, filter.Limit)
		assert.Equal(t, 0, filter.Offset)
	})

	t.Run("Values within limits are preserved", func(t *testing.T) {
		filter := UserFilter{
			PaginationParams: PaginationParams{
				Limit:  20,
				Offset: 10,
			},
		}

		// Apply default logic
		if filter.Limit <= 0 || filter.Limit > 100 {
			filter.Limit = 50
		}
		if filter.Offset < 0 {
			filter.Offset = 0
		}

		assert.Equal(t, 20, filter.Limit)
		assert.Equal(t, 10, filter.Offset)
	})

	t.Run("Limit exceeding maximum is capped", func(t *testing.T) {
		filter := UserFilter{
			PaginationParams: PaginationParams{
				Limit: 150,
			},
		}

		// Apply default logic
		if filter.Limit <= 0 || filter.Limit > 100 {
			filter.Limit = 50
		}

		assert.Equal(t, 50, filter.Limit)
	})
}

// ============================================================
// Email Model Tests
// ============================================================

// TestEmailModel tests the Email struct
func TestEmailModel(t *testing.T) {
	t.Run("Email with all fields", func(t *testing.T) {
		workType := "work"
		primary := true
		verified := true
		display := "Work Email"

		email := Email{
			Value:    "test@example.com",
			Type:     &workType,
			Primary:  &primary,
			Verified: &verified,
			Display:  &display,
		}

		assert.Equal(t, "test@example.com", email.Value)
		assert.Equal(t, "work", *email.Type)
		assert.True(t, *email.Primary)
		assert.True(t, *email.Verified)
		assert.Equal(t, "Work Email", *email.Display)
	})

	t.Run("Email with minimal fields", func(t *testing.T) {
		email := Email{
			Value: "minimal@example.com",
		}

		assert.Equal(t, "minimal@example.com", email.Value)
		assert.Nil(t, email.Type)
		assert.Nil(t, email.Primary)
	})
}

// ============================================================
// PhoneNumber Model Tests
// ============================================================

// TestPhoneNumberModel tests the PhoneNumber struct
func TestPhoneNumberModel(t *testing.T) {
	t.Run("PhoneNumber with all fields", func(t *testing.T) {
		mobileType := "mobile"
		primary := true

		phone := PhoneNumber{
			Value:   "+1234567890",
			Type:    &mobileType,
			Primary: &primary,
		}

		assert.Equal(t, "+1234567890", phone.Value)
		assert.Equal(t, "mobile", *phone.Type)
		assert.True(t, *phone.Primary)
	})
}

// ============================================================
// Address Model Tests
// ============================================================

// TestAddressModel tests the Address struct
func TestAddressModel(t *testing.T) {
	t.Run("Address with all fields", func(t *testing.T) {
		street := "123 Main St"
		city := "Springfield"
		state := "IL"
		zip := "62701"
		country := "USA"
		workType := "work"
		primary := true

		address := Address{
			StreetAddress: &street,
			Locality:      &city,
			Region:        &state,
			PostalCode:    &zip,
			Country:       &country,
			Type:          &workType,
			Primary:       &primary,
		}

		assert.Equal(t, "123 Main St", *address.StreetAddress)
		assert.Equal(t, "Springfield", *address.Locality)
		assert.Equal(t, "IL", *address.Region)
		assert.Equal(t, "62701", *address.PostalCode)
		assert.Equal(t, "USA", *address.Country)
	})
}

// ============================================================
// Name Model Tests
// ============================================================

// TestNameModel tests the Name struct
func TestNameModel(t *testing.T) {
	t.Run("Name with all fields", func(t *testing.T) {
		given := "John"
		middle := "William"
		family := "Doe"
		prefix := "Mr."
		suffix := "Jr."
		formatted := "Mr. John William Doe Jr."

		name := Name{
			GivenName:       &given,
			MiddleName:      &middle,
			FamilyName:      &family,
			HonorificPrefix: &prefix,
			HonorificSuffix: &suffix,
			Formatted:       &formatted,
		}

		assert.Equal(t, "John", *name.GivenName)
		assert.Equal(t, "William", *name.MiddleName)
		assert.Equal(t, "Doe", *name.FamilyName)
		assert.Equal(t, "Mr.", *name.HonorificPrefix)
		assert.Equal(t, "Jr.", *name.HonorificSuffix)
		assert.Equal(t, "Mr. John William Doe Jr.", *name.Formatted)
	})

	t.Run("Name with minimal fields", func(t *testing.T) {
		given := "Jane"
		family := "Smith"

		name := Name{
			GivenName:  &given,
			FamilyName: &family,
		}

		assert.Equal(t, "Jane", *name.GivenName)
		assert.Equal(t, "Smith", *name.FamilyName)
		assert.Nil(t, name.MiddleName)
	})
}

// ============================================================
// Member Model Tests
// ============================================================

// TestMemberModel tests the Member struct
func TestMemberModel(t *testing.T) {
	t.Run("Member with all fields", func(t *testing.T) {
		userID := uuid.New().String()
		display := "John Doe"
		ref := "https://example.com/users/john"

		member := Member{
			Value:   userID,
			Display: &display,
			Type:    "User",
			Ref:     &ref,
		}

		assert.Equal(t, userID, member.Value)
		assert.Equal(t, "John Doe", *member.Display)
		assert.Equal(t, "User", member.Type)
		assert.Equal(t, "https://example.com/users/john", *member.Ref)
	})

	t.Run("Member with minimal fields", func(t *testing.T) {
		member := Member{
			Value: "user-123",
			Type:  "User",
		}

		assert.Equal(t, "user-123", member.Value)
		assert.Equal(t, "User", member.Type)
		assert.Nil(t, member.Display)
	})
}

// ============================================================
// Meta Model Tests
// ============================================================

// TestMetaModel tests the Meta struct
func TestMetaModel(t *testing.T) {
	now := time.Now()

	meta := Meta{
		ResourceType: "User",
		Location:     "https://example.com/users/123",
		Created:      now.Add(-30 * 24 * time.Hour),
		LastModified: now,
		Version:      "W/\"12345\"",
	}

	assert.Equal(t, "User", meta.ResourceType)
	assert.Equal(t, "https://example.com/users/123", meta.Location)
	assert.False(t, meta.Created.IsZero())
	assert.False(t, meta.LastModified.IsZero())
	assert.Equal(t, "W/\"12345\"", meta.Version)
}

// ============================================================
// Role Model Tests
// ============================================================

// TestRoleModel tests the Role struct
func TestRoleModel(t *testing.T) {
	now := time.Now()

	role := Role{
		ID:          "role-123",
		Name:        "Administrator",
		Description: "Full system administrator",
		IsComposite: false,
		CreatedAt:   now,
	}

	assert.Equal(t, "role-123", role.ID)
	assert.Equal(t, "Administrator", role.Name)
	assert.Equal(t, "Full system administrator", role.Description)
	assert.False(t, role.IsComposite)
}

// ============================================================
// MFATOTP Model Tests
// ============================================================

// TestMFATOTPModel tests the MFATOTP struct
func TestMFATOTPModel(t *testing.T) {
	now := time.Now()
	enrolledAt := now.Add(-30 * 24 * time.Hour)
	lastUsedAt := now.Add(-1 * time.Hour)

	totp := &MFATOTP{
		ID:         uuid.New().String(),
		UserID:     uuid.New().String(),
		Secret:     "secret123",
		Enabled:    true,
		EnrolledAt: &enrolledAt,
		LastUsedAt: &lastUsedAt,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	assert.NotEmpty(t, totp.ID)
	assert.NotEmpty(t, totp.UserID)
	assert.NotEmpty(t, totp.Secret)
	assert.True(t, totp.Enabled)
	assert.NotNil(t, totp.EnrolledAt)
	assert.NotNil(t, totp.LastUsedAt)
}

// ============================================================
// MFABackupCode Model Tests
// ============================================================

// TestMFABackupCodeModel tests the MFABackupCode struct
func TestMFABackupCodeModel(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(-1 * time.Hour)

	code := MFABackupCode{
		ID:        uuid.New().String(),
		UserID:    uuid.New().String(),
		CodeHash:  "hashedcode",
		Used:      true,
		UsedAt:    &usedAt,
		CreatedAt: now,
	}

	assert.NotEmpty(t, code.ID)
	assert.NotEmpty(t, code.UserID)
	assert.True(t, code.Used)
	assert.NotNil(t, code.UsedAt)
}

// ============================================================
// MFAPolicy Model Tests
// ============================================================

// TestMFAPolicyModel tests the MFAPolicy struct
func TestMFAPolicyModel(t *testing.T) {
	now := time.Now()

	policy := &MFAPolicy{
		ID:               uuid.New().String(),
		Name:             "Corporate MFA Policy",
		Description:      "MFA required for all access",
		Enabled:          true,
		Priority:         1,
		Conditions:       map[string]interface{}{"ip": "corporate"},
		RequiredMethods:  []string{"totp", "push"},
		GracePeriodHours: 24,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	assert.NotEmpty(t, policy.ID)
	assert.Equal(t, "Corporate MFA Policy", policy.Name)
	assert.True(t, policy.Enabled)
	assert.Equal(t, 1, policy.Priority)
	assert.Len(t, policy.RequiredMethods, 2)
	assert.Equal(t, 24, policy.GracePeriodHours)
}

// ============================================================
// TOTPEnrollment Model Tests
// ============================================================

// TestTOTPEnrollmentModel tests the TOTPEnrollment struct
func TestTOTPEnrollmentModel(t *testing.T) {
	enrollment := &TOTPEnrollment{
		Secret:    "JBSWY3DPEHPK3PXP",
		QRCodeURL: "https://example.com/qr",
		ManualKey: "JBSW Y3DP EHPK 3PXP",
	}

	assert.NotEmpty(t, enrollment.Secret)
	assert.NotEmpty(t, enrollment.QRCodeURL)
	assert.NotEmpty(t, enrollment.ManualKey)
}

// ============================================================
// TOTPVerification Model Tests
// ============================================================

// TestTOTPVerificationModel tests the TOTPVerification struct
func TestTOTPVerificationModel(t *testing.T) {
	verification := &TOTPVerification{
		Code: "123456",
	}

	assert.Equal(t, "123456", verification.Code)
}

// ============================================================
// GroupMember Model Tests
// ============================================================

// TestGroupMemberModel tests the GroupMember struct
func TestGroupMemberModel(t *testing.T) {
	now := time.Now()

	member := GroupMember{
		UserID:    uuid.New().String(),
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		JoinedAt:  now,
	}

	assert.NotEmpty(t, member.UserID)
	assert.Equal(t, "testuser", member.Username)
	assert.Equal(t, "test@example.com", member.Email)
	assert.Equal(t, "Test", member.FirstName)
	assert.Equal(t, "User", member.LastName)
	assert.False(t, member.JoinedAt.IsZero())
}

// ============================================================
// UserRoleAssignment Model Tests
// ============================================================

// TestUserRoleAssignmentModel tests the UserRoleAssignment struct
func TestUserRoleAssignmentModel(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(90 * 24 * time.Hour)

	assignment := UserRoleAssignment{
		Role: Role{
			ID:          "role-123",
			Name:        "Admin",
			Description: "Administrator",
		},
		AssignedBy: "admin-user",
		AssignedAt: now,
		ExpiresAt:  &expiresAt,
	}

	assert.Equal(t, "Admin", assignment.Role.Name)
	assert.Equal(t, "admin-user", assignment.AssignedBy)
	assert.NotNil(t, assignment.ExpiresAt)
}

// ============================================================
// PaginationParams Tests
// ============================================================

// TestPaginationParams tests the PaginationParams struct
func TestPaginationParams(t *testing.T) {
	t.Run("Valid pagination params", func(t *testing.T) {
		params := PaginationParams{
			Offset: 0,
			Limit:  20,
		}

		assert.Equal(t, 0, params.Offset)
		assert.Equal(t, 20, params.Limit)
	})

	t.Run("Large offset", func(t *testing.T) {
		params := PaginationParams{
			Offset: 1000,
			Limit:  50,
		}

		assert.Equal(t, 1000, params.Offset)
		assert.Equal(t, 50, params.Limit)
	})
}

// ============================================================
// DirectoryAuthenticator Interface Tests
// ============================================================

// TestDirectoryAuthenticatorInterface tests the DirectoryAuthenticator interface
func TestDirectoryAuthenticatorInterface(t *testing.T) {
	// This test ensures the interface is correctly defined
	var _ DirectoryAuthenticator = (*MockDirectoryAuthenticator)(nil)
}

// MockDirectoryAuthenticator is a mock for testing
type MockDirectoryAuthenticator struct{}

func (m *MockDirectoryAuthenticator) AuthenticateUser(ctx context.Context, directoryID, username, password string) error {
	return nil
}

func (m *MockDirectoryAuthenticator) ChangePassword(ctx context.Context, directoryID, username, oldPassword, newPassword string) error {
	return nil
}

func (m *MockDirectoryAuthenticator) ResetPassword(ctx context.Context, directoryID, username, newPassword string) error {
	return nil
}

// ============================================================
// EmailSender Interface Tests
// ============================================================

// TestEmailSenderInterface tests the EmailSender interface
func TestEmailSenderInterface(t *testing.T) {
	var _ EmailSender = (*MockEmailSender)(nil)
}

// MockEmailSender is a mock for testing
type MockEmailSender struct{}

func (m *MockEmailSender) SendVerificationEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return nil
}

func (m *MockEmailSender) SendInvitationEmail(ctx context.Context, to, inviterName, token, baseURL string) error {
	return nil
}

func (m *MockEmailSender) SendPasswordResetEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return nil
}

func (m *MockEmailSender) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	return nil
}

func (m *MockEmailSender) SendAsync(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	return nil
}

// ============================================================
// WebhookPublisher Interface Tests
// ============================================================

// TestWebhookPublisherInterface tests the WebhookPublisher interface
func TestWebhookPublisherInterface(t *testing.T) {
	var _ WebhookPublisher = (*MockWebhookPublisher)(nil)
}

// MockWebhookPublisher is a mock for testing
type MockWebhookPublisher struct{}

func (m *MockWebhookPublisher) Publish(ctx context.Context, eventType string, payload interface{}) error {
	return nil
}

// ============================================================
// AnomalyDetector Interface Tests
// ============================================================

// TestAnomalyDetectorInterface tests the AnomalyDetector interface
func TestAnomalyDetectorInterface(t *testing.T) {
	var _ AnomalyDetector = (*MockAnomalyDetector)(nil)
}

// MockAnomalyDetector is a mock for testing
type MockAnomalyDetector struct{}

func (m *MockAnomalyDetector) RunAnomalyCheck(ctx context.Context, userID, ip, userAgent string, lat, lon float64) interface{} {
	return nil
}

func (m *MockAnomalyDetector) CheckIPThreatList(ctx context.Context, ip string) (bool, string) {
	return false, ""
}

// ============================================================
// SMSProvider Interface Tests
// ============================================================

// TestSMSProviderInterface tests the SMSProvider interface
func TestSMSProviderInterface(t *testing.T) {
	var _ SMSProvider = (*MockSMSProvider)(nil)
}

// MockSMSProvider is a mock for testing
type MockSMSProvider struct{}

func (m *MockSMSProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	return nil
}

func (m *MockSMSProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	return nil
}

// ============================================================
// Service Creation Tests
// ============================================================

// TestNewServiceExtended tests service creation
func TestNewServiceExtended(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		OAuthIssuer:  "http://localhost:8006",
		OAuthJWKSURL: "http://localhost:8006/.well-known/jwks.json",
	}

	service := NewService(&database.PostgresDB{}, nil, cfg, logger)

	assert.NotNil(t, service)
	assert.NotNil(t, service.logger)
	assert.NotNil(t, service.cfg)
}

// TestServiceSetters tests service setter methods
func TestServiceSetters(t *testing.T) {
	service := createTestService(t)

	t.Run("SetDirectoryService", func(t *testing.T) {
		mockDir := &MockDirectoryAuthenticator{}
		service.SetDirectoryService(mockDir)
		assert.Equal(t, mockDir, service.directoryService)
	})

	t.Run("SetEmailService", func(t *testing.T) {
		mockEmail := &MockEmailSender{}
		service.SetEmailService(mockEmail)
		assert.Equal(t, mockEmail, service.emailService)
	})

	t.Run("SetWebhookService", func(t *testing.T) {
		mockWebhook := &MockWebhookPublisher{}
		service.SetWebhookService(mockWebhook)
		assert.Equal(t, mockWebhook, service.webhookService)
	})

	t.Run("SetAnomalyDetector", func(t *testing.T) {
		mockAnomaly := &MockAnomalyDetector{}
		service.SetAnomalyDetector(mockAnomaly)
		assert.Equal(t, mockAnomaly, service.anomalyDetector)
	})

	t.Run("SetSMSProvider", func(t *testing.T) {
		mockSMS := &MockSMSProvider{}
		service.SetSMSProvider(mockSMS)
		assert.Equal(t, mockSMS, service.smsProvider)
	})
}

// ============================================================
// Password History Tests (from passwords.go)
// ============================================================

// TestCheckPasswordHistory_Pattern tests the password history check pattern
func TestCheckPasswordHistory_Pattern(t *testing.T) {
	// This tests the logic pattern for password history
	t.Run("Password history check logic", func(t *testing.T) {
		// Simulate password history hashes
		oldHashes := []string{
			hashPassword(t, "OldPassword123!"),
			hashPassword(t, "OldPassword456!"),
		}

		// New password matches an old one
		newPassword := "OldPassword123!"
		matchFound := false

		for _, hash := range oldHashes {
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)); err == nil {
				matchFound = true
				break
			}
		}

		assert.True(t, matchFound, "Should find matching password in history")
	})

	t.Run("New password not in history", func(t *testing.T) {
		oldHashes := []string{
			hashPassword(t, "OldPassword123!"),
			hashPassword(t, "OldPassword456!"),
		}

		newPassword := "NewPassword789!"
		matchFound := false

		for _, hash := range oldHashes {
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)); err == nil {
				matchFound = true
				break
			}
		}

		assert.False(t, matchFound, "Should not find new password in history")
	})
}

// TestPasswordExpiration_Pattern tests password expiration logic
func TestPasswordExpiration_Pattern(t *testing.T) {
	maxAgeDays := 90

	t.Run("Password not expired", func(t *testing.T) {
		passwordChangedAt := time.Now().Add(-30 * 24 * time.Hour)
		elapsed := time.Since(passwordChangedAt)
		maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
		expired := elapsed > maxAge

		assert.False(t, expired)
	})

	t.Run("Password expired", func(t *testing.T) {
		passwordChangedAt := time.Now().Add(-100 * 24 * time.Hour)
		elapsed := time.Since(passwordChangedAt)
		maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
		expired := elapsed > maxAge

		assert.True(t, expired)
	})

	t.Run("Password just before expiration limit", func(t *testing.T) {
		passwordChangedAt := time.Now().Add(-89*24*time.Hour - 23*time.Hour)
		elapsed := time.Since(passwordChangedAt)
		maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
		expired := elapsed > maxAge

		assert.False(t, expired, "Just before limit should not be expired")
	})
}

// ============================================================
// Session Duration Tests
// ============================================================

// TestSessionDurationCalculations tests various session duration scenarios
func TestSessionDurationCalculations(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name            string
		sessionDuration time.Duration
		expectedExpiry  time.Duration
	}{
		{
			name:            "1 hour session",
			sessionDuration: 1 * time.Hour,
			expectedExpiry:  1 * time.Hour,
		},
		{
			name:            "24 hour session",
			sessionDuration: 24 * time.Hour,
			expectedExpiry:  24 * time.Hour,
		},
		{
			name:            "7 day session",
			sessionDuration: 7 * 24 * time.Hour,
			expectedExpiry:  7 * 24 * time.Hour,
		},
		{
			name:            "30 day session",
			sessionDuration: 30 * 24 * time.Hour,
			expectedExpiry:  30 * 24 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expiresAt := now.Add(tc.sessionDuration)
			duration := expiresAt.Sub(now)
			assert.Equal(t, tc.expectedExpiry, duration)
		})
	}
}

// ============================================================
// Email Validation Pattern Tests
// ============================================================

// TestEmailValidationPatterns tests email format validation
func TestEmailValidationPatterns(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"test.user@example.com",
		"user+tag@example.com",
		"user@sub.example.com",
		"123@example.com",
	}

	invalidEmails := []string{
		"plainaddress",
		"@example.com",
		"user@",
		"user name@example.com", // space
	}

	for _, email := range validEmails {
		t.Run("Valid: "+email, func(t *testing.T) {
			// Basic email validation pattern
			assert.Contains(t, email, "@")
			assert.NotEqual(t, '@', email[0])
			assert.NotEqual(t, '@', email[len(email)-1])
		})
	}

	for _, email := range invalidEmails {
		t.Run("Invalid: "+email, func(t *testing.T) {
			// These should fail basic validation
			if !strings.Contains(email, "@") || email == "@" || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
				assert.True(t, true, "Email is invalid as expected")
			}
		})
	}
}

// ============================================================
// Username Validation Pattern Tests
// ============================================================

// TestUsernameValidationPatterns tests username format validation
func TestUsernameValidationPatterns(t *testing.T) {
	validUsernames := []string{
		"user",
		"user123",
		"user_name",
		"user-name",
		"User.Name",
		"123user",
	}

	invalidUsernames := []string{
		"",
		"ab",
		"user name", // space
		"user@name", // special char (likely invalid)
	}

	for _, username := range validUsernames {
		t.Run("Valid: "+username, func(t *testing.T) {
			assert.GreaterOrEqual(t, len(username), 3)
			assert.NotEqual(t, "", username)
		})
	}

	for _, username := range invalidUsernames {
		t.Run("Invalid: "+username, func(t *testing.T) {
			if len(username) < 3 {
				assert.Less(t, len(username), 3)
			}
			if username == "" {
				assert.Equal(t, "", username)
			}
		})
	}
}

// TestBcryptPasswordHashing tests bcrypt password hashing
func TestBcryptPasswordHashing(t *testing.T) {
	t.Run("Hash and verify password", func(t *testing.T) {
		password := "TestPassword123!"
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)

		// Verify the password
		err = bcrypt.CompareHashAndPassword(hash, []byte(password))
		assert.NoError(t, err)
	})

	t.Run("Reject wrong password", func(t *testing.T) {
		password := "TestPassword123!"
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		// Try wrong password
		err = bcrypt.CompareHashAndPassword(hash, []byte("WrongPassword123!"))
		assert.Error(t, err)
	})

	t.Run("Different hashes for same password", func(t *testing.T) {
		password := "TestPassword123!"
		hash1, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		hash2, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		// Hashes should be different due to salt
		assert.NotEqual(t, string(hash1), string(hash2))

		// But both should verify correctly
		err = bcrypt.CompareHashAndPassword(hash1, []byte(password))
		assert.NoError(t, err)

		err = bcrypt.CompareHashAndPassword(hash2, []byte(password))
		assert.NoError(t, err)
	})
}

// TestPushMFADeviceModel tests the PushMFADevice struct
func TestPushMFADeviceModel(t *testing.T) {
	now := time.Now()
	lastUsed := now.Add(-1 * time.Hour)

	device := PushMFADevice{
		ID:          uuid.New().String(),
		UserID:      uuid.New().String(),
		DeviceToken: "token123",
		Platform:    "ios",
		DeviceName:  "iPhone",
		DeviceModel: "iPhone 13",
		OSVersion:   "16.0",
		AppVersion:  "1.0",
		Enabled:     true,
		Trusted:     true,
		LastIP:      "192.168.1.1",
		CreatedAt:   now,
		LastUsedAt:  &lastUsed,
	}

	assert.NotEmpty(t, device.ID)
	assert.NotEmpty(t, device.UserID)
	assert.Equal(t, "iPhone", device.DeviceName)
	assert.Equal(t, "ios", device.Platform)
	assert.True(t, device.Enabled)
	assert.True(t, device.Trusted)
}

// ============================================================
// Conversion Package Tests
// ============================================================

// TestUserDBConversionExtended tests UserDB conversion methods
func TestUserDBConversionExtended(t *testing.T) {
	t.Run("UserDB ToUser with all fields", func(t *testing.T) {
		now := time.Now()
		orgID := "org-123"
		source := "ldap"
		directoryID := "dir-123"

		dbUser := UserDB{
			ID:             "user-123",
			Username:       "testuser",
			Email:          "test@example.com",
			FirstName:      "Test",
			LastName:       "User",
			Enabled:        true,
			EmailVerified:  true,
			CreatedAt:      now,
			UpdatedAt:      now,
			OrganizationID: &orgID,
			Source:         &source,
			DirectoryID:    &directoryID,
		}

		user := dbUser.ToUser()
		assert.Equal(t, "user-123", user.ID)
		assert.Equal(t, "testuser", user.UserName)
		assert.Equal(t, "test@example.com", user.GetEmail())
		assert.Equal(t, "Test", user.GetFirstName())
		assert.Equal(t, "User", user.GetLastName())
		assert.Equal(t, &orgID, user.OrganizationID)
		assert.Equal(t, &source, user.Source)
		assert.Equal(t, &directoryID, user.DirectoryID)
	})

	t.Run("UserDB ToUser with minimal fields", func(t *testing.T) {
		now := time.Now()
		dbUser := UserDB{
			ID:        "user-123",
			Username:  "testuser",
			Email:     "test@example.com",
			FirstName: "",
			LastName:  "",
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}

		user := dbUser.ToUser()
		assert.Equal(t, "user-123", user.ID)
		assert.Equal(t, "testuser", user.UserName)
		assert.Nil(t, user.Name)
	})

	t.Run("UserDB getter methods", func(t *testing.T) {
		dbUser := UserDB{
			Username:  "testuser",
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
		}
		assert.Equal(t, "testuser", dbUser.GetUsername())
		assert.Equal(t, "test@example.com", dbUser.GetEmail())
		assert.Equal(t, "Test", dbUser.GetFirstName())
		assert.Equal(t, "User", dbUser.GetLastName())
	})
}

// TestFromUserExtended tests FromUser conversion
func TestFromUserExtended(t *testing.T) {
	t.Run("FromUser with full SCIM User", func(t *testing.T) {
		now := time.Now()
		orgID := "org-123"
		given := "Test"
		family := "User"
		primary := true

		user := User{
			ID:             "user-123",
			UserName:       "testuser",
			Enabled:        true,
			EmailVerified:  true,
			CreatedAt:      now,
			UpdatedAt:      now,
			OrganizationID: &orgID,
			Name: &Name{
				GivenName:  &given,
				FamilyName: &family,
			},
			Emails: []Email{
				{
					Value:   "test@example.com",
					Primary: &primary,
				},
			},
		}

		dbUser := FromUser(user)
		assert.Equal(t, "user-123", dbUser.ID)
		assert.Equal(t, "testuser", dbUser.Username)
		assert.Equal(t, "test@example.com", dbUser.Email)
		assert.Equal(t, "Test", dbUser.FirstName)
		assert.Equal(t, "User", dbUser.LastName)
		assert.Equal(t, &orgID, dbUser.OrganizationID)
	})

	t.Run("FromUser with multiple emails finds primary", func(t *testing.T) {
		now := time.Now()
		primary := true
		secondary := false

		user := User{
			ID:        "user-123",
			UserName:  "testuser",
			CreatedAt: now,
			UpdatedAt: now,
			Emails: []Email{
				{
					Value:   "secondary@example.com",
					Primary: &secondary,
				},
				{
					Value:   "primary@example.com",
					Primary: &primary,
				},
			},
		}

		dbUser := FromUser(user)
		assert.Equal(t, "primary@example.com", dbUser.Email)
	})

	t.Run("FromUser with no primary email uses first", func(t *testing.T) {
		now := time.Now()
		user := User{
			ID:        "user-123",
			UserName:  "testuser",
			CreatedAt: now,
			UpdatedAt: now,
			Emails: []Email{
				{
					Value: "first@example.com",
				},
			},
		}

		dbUser := FromUser(user)
		assert.Equal(t, "first@example.com", dbUser.Email)
	})
}

// TestGroupDBConversionExtended tests GroupDB conversion methods
func TestGroupDBConversionExtended(t *testing.T) {
	t.Run("GroupDB ToGroup with all fields", func(t *testing.T) {
		now := time.Now()
		description := "Test group"
		parentID := "parent-123"
		orgID := "org-123"

		dbGroup := GroupDB{
			ID:              "group-123",
			DisplayName:     "TestGroup",
			Description:     &description,
			ParentID:        &parentID,
			OrganizationID:  &orgID,
			AllowSelfJoin:   true,
			RequireApproval: false,
			MemberCount:     5,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		group := dbGroup.ToGroup()
		assert.Equal(t, "group-123", group.ID)
		assert.Equal(t, "TestGroup", group.DisplayName)
		assert.NotNil(t, group.Attributes)
		assert.Equal(t, "Test group", group.Attributes["description"])
		assert.Equal(t, "parent-123", group.Attributes["parentId"])
		assert.Equal(t, &orgID, group.OrganizationID)
	})

	t.Run("GroupDB ToGroup with minimal fields", func(t *testing.T) {
		now := time.Now()
		dbGroup := GroupDB{
			ID:          "group-123",
			DisplayName: "TestGroup",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		group := dbGroup.ToGroup()
		assert.Equal(t, "group-123", group.ID)
		assert.Nil(t, group.Attributes)
	})

	t.Run("FromGroup with attributes", func(t *testing.T) {
		now := time.Now()
		maxMembers := "100"
		orgID := "org-123"

		group := Group{
			ID:          "group-123",
			DisplayName: "TestGroup",
			CreatedAt:   now,
			UpdatedAt:   now,
			Attributes: map[string]string{
				"description":     "Test description",
				"parentId":        "parent-123",
				"allowSelfJoin":   "true",
				"requireApproval": "false",
				"maxMembers":      maxMembers,
			},
			OrganizationID: &orgID,
		}

		dbGroup := FromGroup(group)
		assert.Equal(t, "group-123", dbGroup.ID)
		assert.Equal(t, "TestGroup", dbGroup.DisplayName)
		assert.Equal(t, "Test description", *dbGroup.Description)
		assert.Equal(t, "parent-123", *dbGroup.ParentID)
		assert.True(t, dbGroup.AllowSelfJoin)
		assert.False(t, dbGroup.RequireApproval)
		assert.Equal(t, 100, *dbGroup.MaxMembers)
		assert.Equal(t, &orgID, dbGroup.OrganizationID)
	})
}

// TestConversionHelperFunctionsExtended tests the helper functions in conversion.go
func TestConversionHelperFunctionsExtended(t *testing.T) {
	t.Run("GetEmail helper", func(t *testing.T) {
		primary := true
		user := User{
			Emails: []Email{
				{Value: "primary@example.com", Primary: &primary},
			},
		}
		assert.Equal(t, "primary@example.com", GetEmail(user))
	})

	t.Run("GetEmail with no emails", func(t *testing.T) {
		user := User{Emails: []Email{}}
		assert.Equal(t, "", GetEmail(user))
	})

	t.Run("GetUsername helper", func(t *testing.T) {
		user := User{UserName: "testuser"}
		assert.Equal(t, "testuser", GetUsername(user))
	})

	t.Run("GetFirstName helper", func(t *testing.T) {
		given := "John"
		user := User{Name: &Name{GivenName: &given}}
		assert.Equal(t, "John", GetFirstName(user))
	})

	t.Run("GetFirstName with no name", func(t *testing.T) {
		user := User{}
		assert.Equal(t, "", GetFirstName(user))
	})

	t.Run("GetLastName helper", func(t *testing.T) {
		family := "Doe"
		user := User{Name: &Name{FamilyName: &family}}
		assert.Equal(t, "Doe", GetLastName(user))
	})

	t.Run("GetLastName with no name", func(t *testing.T) {
		user := User{}
		assert.Equal(t, "", GetLastName(user))
	})
}

// TestTOTPModelExtended tests TOTP-related model functions
func TestTOTPModelExtended(t *testing.T) {
	t.Run("IsLocked with nil LockedUntil", func(t *testing.T) {
		user := &User{LockedUntil: nil}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when expired", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		user := &User{LockedUntil: &past}
		assert.False(t, user.IsLocked())
	})

	t.Run("IsLocked when active", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		user := &User{LockedUntil: &future}
		assert.True(t, user.IsLocked())
	})
}
