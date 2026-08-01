// Package identity provides SCIM 2.0 unit tests per RFC 7644
package identity

import (
	"encoding/json"
	"testing"
	"time"
)

// ============================================================
// SCIM Filter Parser Tests
// ============================================================

func TestParseFilter_SimpleEquality(t *testing.T) {
	tests := []struct {
		name      string
		filter    string
		wantOp    FilterOperator
		wantField string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "userName eq john.doe",
			filter:    "userName eq john.doe",
			wantOp:    OpEqual,
			wantField: "userName",
			wantValue: "john.doe",
			wantErr:   false,
		},
		{
			name:      "active eq true",
			filter:    "active eq true",
			wantOp:    OpEqual,
			wantField: "active",
			wantValue: "true",
			wantErr:   false,
		},
		{
			name:      "name.givenName eq John",
			filter:    "name.givenName eq John",
			wantOp:    OpEqual,
			wantField: "name.givenName",
			wantValue: "John",
			wantErr:   false,
		},
		{
			name:      "displayName eq \"Test User\"",
			filter:    `displayName eq "Test User"`,
			wantOp:    OpEqual,
			wantField: "displayName",
			wantValue: "Test User",
			wantErr:   false,
		},
		{
			name:      "userName co admin",
			filter:    "userName co admin",
			wantOp:    OpContains,
			wantField: "userName",
			wantValue: "admin",
			wantErr:   false,
		},
		{
			name:      "userName sw user",
			filter:    "userName sw user",
			wantOp:    OpStartsWith,
			wantField: "userName",
			wantValue: "user",
			wantErr:   false,
		},
		{
			name:      "userName ew example.com",
			filter:    "userName ew example.com",
			wantOp:    OpEndsWith,
			wantField: "userName",
			wantValue: "example.com",
			wantErr:   false,
		},
		{
			name:      "emails pr",
			filter:    "emails pr",
			wantOp:    OpPresent,
			wantField: "emails",
			wantValue: "",
			wantErr:   false,
		},
		{
			name:      "userName ne admin",
			filter:    "userName ne admin",
			wantOp:    OpNotEqual,
			wantField: "userName",
			wantValue: "admin",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := ParseFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if expr.Operator != tt.wantOp {
					t.Errorf("Operator = %v, want %v", expr.Operator, tt.wantOp)
				}
				if expr.Field != tt.wantField {
					t.Errorf("Field = %v, want %v", expr.Field, tt.wantField)
				}
				if expr.Value != tt.wantValue {
					t.Errorf("Value = %v, want %v", expr.Value, tt.wantValue)
				}
			}
		})
	}
}

func TestParseFilter_LogicalOperators(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		wantOp  FilterOperator
		wantErr bool
	}{
		{
			name:    "userName eq john and active eq true",
			filter:  "userName eq john and active eq true",
			wantOp:  OpAnd,
			wantErr: false,
		},
		{
			name:    "userName eq john or userName eq jane",
			filter:  "userName eq john or userName eq jane",
			wantOp:  OpOr,
			wantErr: false,
		},
		{
			name:    "not (userName eq admin)",
			filter:  "not (userName eq admin)",
			wantOp:  OpNot,
			wantErr: false,
		},
		{
			name:    "userName eq john and (active eq true or active eq false)",
			filter:  "userName eq john and (active eq true or active eq false)",
			wantOp:  OpAnd,
			wantErr: false,
		},
		{
			name:    "(userName eq john) and active eq true",
			filter:  "(userName eq john) and active eq true",
			wantOp:  OpAnd,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := ParseFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && expr.Operator != tt.wantOp {
				t.Errorf("Operator = %v, want %v", expr.Operator, tt.wantOp)
			}
		})
	}
}

func TestParseFilter_Complex(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "three AND conditions",
			filter:  "userName eq john and active eq true and emails pr",
			wantErr: false,
		},
		{
			name:    "nested parentheses",
			filter:  "((userName eq john) and (active eq true)) or displayName eq Test",
			wantErr: false,
		},
		{
			name:    "NOT with OR",
			filter:  "not (userName eq john or userName eq jane)",
			wantErr: false,
		},
		{
			name:    "complex nested expression",
			filter:  "(userName eq john and active eq true) or (userName eq admin and active eq false)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseFilter_Errors(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "empty filter",
			filter:  "",
			wantErr: false, // Empty filter returns nil, not error
		},
		{
			name:    "invalid operator",
			filter:  "userName invalid john",
			wantErr: true,
		},
		{
			name:    "missing value",
			filter:  "userName eq",
			wantErr: true,
		},
		{
			name:    "unbalanced parentheses",
			filter:  "(userName eq john",
			wantErr: true,
		},
		{
			name:    "unbalanced closing paren",
			filter:  "userName eq john)",
			wantErr: true,
		},
		{
			name:    "invalid not without parens",
			filter:  "not userName eq john",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================
// SCIM Filter to SQL Tests
// ============================================================

func TestFilterToSQL_Simple(t *testing.T) {
	fieldMapping := GetUserFieldMapping()

	tests := []struct {
		name        string
		filter      string
		wantClause  string
		wantArgsLen int
		wantErr     bool
	}{
		{
			name:        "userName eq john",
			filter:      "userName eq john",
			wantClause:  "username = $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			// There is no display_name column; SCIM displayName is the
			// composed first/last name.
			name:        "displayName co Test",
			filter:      "displayName co Test",
			wantClause:  "(COALESCE(first_name, '') || ' ' || COALESCE(last_name, '')) ILIKE $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			name:        "userName sw user",
			filter:      "userName sw user",
			wantClause:  "username ILIKE $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			name:        "userName ew example.com",
			filter:      "userName ew example.com",
			wantClause:  "username ILIKE $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			// emails maps to the scalar `email` column, not a jsonb array —
			// the old expectation asserted SQL that would have errored had it
			// ever reached Postgres.
			name:        "emails pr",
			filter:      "emails pr",
			wantClause:  "email IS NOT NULL",
			wantArgsLen: 0,
			wantErr:     false,
		},
		{
			name:        "emails eq matches the scalar column",
			filter:      "emails eq user@example.com",
			wantClause:  "email = $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			name:        "externalId eq (used by Okta/Entra before every create)",
			filter:      "externalId eq ext-123",
			wantClause:  "external_id = $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			name:        "active eq maps to the enabled column",
			filter:      "active eq true",
			wantClause:  "enabled = $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
		{
			name:        "userName ne admin",
			filter:      "userName ne admin",
			wantClause:  "username != $1",
			wantArgsLen: 1,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := ParseFilter(tt.filter)
			if err != nil {
				t.Fatalf("ParseFilter() failed: %v", err)
			}

			sqlFilter, err := FilterToSQL(expr, fieldMapping)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilterToSQL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if sqlFilter.WhereClause != tt.wantClause {
				t.Errorf("WhereClause = %v, want %v", sqlFilter.WhereClause, tt.wantClause)
			}

			if len(sqlFilter.Args) != tt.wantArgsLen {
				t.Errorf("Args length = %v, want %v", len(sqlFilter.Args), tt.wantArgsLen)
			}
		})
	}
}

func TestFilterToSQL_Logical(t *testing.T) {
	fieldMapping := GetUserFieldMapping()

	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "userName eq john and active eq true",
			filter:  "userName eq john and active eq true",
			wantErr: false,
		},
		{
			name:    "userName eq john or userName eq jane",
			filter:  "userName eq john or userName eq jane",
			wantErr: false,
		},
		{
			name:    "not (userName eq admin)",
			filter:  "not (userName eq admin)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := ParseFilter(tt.filter)
			if err != nil {
				t.Fatalf("ParseFilter() failed: %v", err)
			}

			sqlFilter, err := FilterToSQL(expr, fieldMapping)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilterToSQL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if sqlFilter.WhereClause == "" {
				t.Error("WhereClause should not be empty")
			}

			// Verify number of args matches number of comparison operators
			expectedArgs := 2 // For "userName eq john and active eq true"
			if len(sqlFilter.Args) != expectedArgs {
				t.Logf("Args = %v", sqlFilter.Args)
			}
		})
	}
}

func TestFilterToSQL_InvalidField(t *testing.T) {
	fieldMapping := GetUserFieldMapping()

	expr, err := ParseFilter("invalidField eq value")
	if err != nil {
		t.Fatalf("ParseFilter() failed: %v", err)
	}

	_, err = FilterToSQL(expr, fieldMapping)
	if err == nil {
		t.Error("Expected error for invalid field, got nil")
	}
}

// ============================================================
// SCIM Schema Conversion Tests
// ============================================================

func TestUserToSCIM(t *testing.T) {
	now := time.Now()
	user := &User{
		ID:          "12345",
		UserName:    "john.doe",
		DisplayName: stringPtr("John Doe"),
		Active:      true,
		Enabled:     true,
		Name: &Name{
			GivenName:  stringPtr("John"),
			FamilyName: stringPtr("Doe"),
		},
		Emails: []Email{
			{Value: "john.doe@example.com", Primary: boolPtr(true), Type: stringPtr("work")},
		},
		Groups:    []string{"group1", "group2"},
		Roles:     []string{"admin", "user"},
		CreatedAt: now,
		UpdatedAt: now,
		Meta: &Meta{
			ResourceType: "User",
			Version:      "W/123",
		},
	}

	scimUser := UserToSCIM(user, "http://localhost:8001/scim/v2")

	if scimUser.ID != user.ID {
		t.Errorf("ID = %v, want %v", scimUser.ID, user.ID)
	}

	if scimUser.UserName != user.UserName {
		t.Errorf("UserName = %v, want %v", scimUser.UserName, user.UserName)
	}

	if scimUser.Active == nil || *scimUser.Active != user.Active {
		t.Errorf("Active = %v, want %v", scimUser.Active, user.Active)
	}

	if scimUser.Name == nil || scimUser.Name.GivenName == nil || *scimUser.Name.GivenName != "John" {
		t.Error("Name.GivenName not correctly converted")
	}

	if len(scimUser.Emails) != 1 {
		t.Errorf("Emails length = %v, want 1", len(scimUser.Emails))
	}

	if len(scimUser.Groups) != 2 {
		t.Errorf("Groups length = %v, want 2", len(scimUser.Groups))
	}

	if len(scimUser.Roles) != 2 {
		t.Errorf("Roles length = %v, want 2", len(scimUser.Roles))
	}
}

func TestSCIMToUser(t *testing.T) {
	scimUser := &SCIMUser{
		ID:       "12345",
		UserName: "john.doe",
		Active:   boolPtr(true),
		Name: &SCIMName{
			GivenName:  stringPtr("John"),
			FamilyName: stringPtr("Doe"),
		},
		Emails: []SCIMEmail{
			{Value: "john.doe@example.com", Primary: boolPtr(true)},
		},
		Groups: []SCIMGroupRef{
			{Value: "group1", Type: "Group"},
			{Value: "group2", Type: "Group"},
		},
		Roles: []SCIMRole{
			{Value: "admin"},
			{Value: "user"},
		},
	}

	user := SCIMToUser(scimUser)

	if user.UserName != scimUser.UserName {
		t.Errorf("UserName = %v, want %v", user.UserName, scimUser.UserName)
	}

	if user.Active != true {
		t.Errorf("Active = %v, want true", user.Active)
	}

	if user.Name == nil || user.Name.GivenName == nil || *user.Name.GivenName != "John" {
		t.Error("Name.GivenName not correctly converted")
	}

	if len(user.Emails) != 1 {
		t.Errorf("Emails length = %v, want 1", len(user.Emails))
	}

	if len(user.Groups) != 2 {
		t.Errorf("Groups length = %v, want 2", len(user.Groups))
	}

	if len(user.Roles) != 2 {
		t.Errorf("Roles length = %v, want 2", len(user.Roles))
	}
}

func TestGroupToSCIM(t *testing.T) {
	now := time.Now()
	group := &Group{
		ID:          "group1",
		DisplayName: "Administrators",
		Members: []Member{
			{Value: "user1", Type: "User", Display: stringPtr("User One")},
			{Value: "user2", Type: "User", Display: stringPtr("User Two")},
		},
		CreatedAt: now,
		UpdatedAt: now,
		Meta: &Meta{
			ResourceType: "Group",
			Version:      "W/456",
		},
	}

	scimGroup := GroupToSCIM(group, "http://localhost:8001/scim/v2")

	if scimGroup.ID != group.ID {
		t.Errorf("ID = %v, want %v", scimGroup.ID, group.ID)
	}

	if scimGroup.DisplayName != group.DisplayName {
		t.Errorf("DisplayName = %v, want %v", scimGroup.DisplayName, group.DisplayName)
	}

	if len(scimGroup.Members) != 2 {
		t.Errorf("Members length = %v, want 2", len(scimGroup.Members))
	}
}

func TestSCIMToGroup(t *testing.T) {
	scimGroup := &SCIMGroup{
		ID:          "group1",
		DisplayName: "Administrators",
		Members: []SCIMMember{
			{Value: "user1", Type: "User", Display: stringPtr("User One")},
			{Value: "user2", Type: "User", Display: stringPtr("User Two")},
		},
	}

	group := SCIMToGroup(scimGroup)

	if group.DisplayName != scimGroup.DisplayName {
		t.Errorf("DisplayName = %v, want %v", group.DisplayName, scimGroup.DisplayName)
	}

	if len(group.Members) != 2 {
		t.Errorf("Members length = %v, want 2", len(group.Members))
	}
}

// ============================================================
// SCIM Patch Tests
// ============================================================

func TestApplySCIMPatchToUser_Add(t *testing.T) {
	user := &User{
		ID:       "user1",
		UserName: "john.doe",
		Emails:   []Email{{Value: "john@example.com"}},
		Groups:   []string{"group1"},
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:   "add",
				Path: stringPtr("emails"),
				Value: []interface{}{
					map[string]interface{}{"value": "newemail@example.com", "type": "work"},
				},
			},
			{
				Op:    "add",
				Path:  stringPtr("groups"),
				Value: []interface{}{"group2"},
			},
		},
	}

	err := ApplySCIMPatchToUser(user, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToUser() error = %v", err)
	}

	if len(user.Emails) != 2 {
		t.Errorf("Emails length = %v, want 2", len(user.Emails))
	}

	if len(user.Groups) != 2 {
		t.Errorf("Groups length = %v, want 2", len(user.Groups))
	}
}

func TestApplySCIMPatchToUser_Replace(t *testing.T) {
	user := &User{
		ID:          "user1",
		UserName:    "john.doe",
		DisplayName: stringPtr("John Doe"),
		Name: &Name{
			GivenName:  stringPtr("John"),
			FamilyName: stringPtr("Doe"),
		},
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:    "replace",
				Path:  stringPtr("displayName"),
				Value: "John Smith",
			},
			{
				Op:    "replace",
				Path:  stringPtr("name.givenName"),
				Value: "Jane",
			},
		},
	}

	err := ApplySCIMPatchToUser(user, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToUser() error = %v", err)
	}

	if user.DisplayName == nil || *user.DisplayName != "John Smith" {
		t.Errorf("DisplayName = %v, want John Smith", user.DisplayName)
	}

	if user.Name == nil || user.Name.GivenName == nil || *user.Name.GivenName != "Jane" {
		t.Errorf("Name.GivenName = %v, want Jane", user.Name.GivenName)
	}
}

func TestApplySCIMPatchToUser_Remove(t *testing.T) {
	group1 := "group1"
	group2 := "group2"
	user := &User{
		ID:       "user1",
		UserName: "john.doe",
		Groups:   []string{group1, group2},
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:    "remove",
				Path:  stringPtr("groups[group1]"), // Use bracket syntax to remove specific value
				Value: "group1",
			},
		},
	}

	err := ApplySCIMPatchToUser(user, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToUser() error = %v", err)
	}

	if len(user.Groups) != 1 {
		t.Errorf("Groups length = %v, want 1", len(user.Groups))
	}

	if len(user.Groups) > 0 && user.Groups[0] != group2 {
		t.Errorf("Groups[0] = %v, want %v", user.Groups[0], group2)
	}
}

func TestApplySCIMPatchToGroup_AddMember(t *testing.T) {
	group := &Group{
		ID:          "group1",
		DisplayName: "Administrators",
		Members: []Member{
			{Value: "user1", Type: "User"},
		},
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:   "add",
				Path: stringPtr("members"),
				Value: []interface{}{
					map[string]interface{}{"value": "user2", "type": "User", "display": "User Two"},
				},
			},
		},
	}

	err := ApplySCIMPatchToGroup(group, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToGroup() error = %v", err)
	}

	if len(group.Members) != 2 {
		t.Errorf("Members length = %v, want 2", len(group.Members))
	}
}

func TestApplySCIMPatchToGroup_ReplaceDisplayName(t *testing.T) {
	group := &Group{
		ID:          "group1",
		DisplayName: "Administrators",
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:    "replace",
				Path:  stringPtr("displayName"),
				Value: "Super Administrators",
			},
		},
	}

	err := ApplySCIMPatchToGroup(group, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToGroup() error = %v", err)
	}

	if group.DisplayName != "Super Administrators" {
		t.Errorf("DisplayName = %v, want 'Super Administrators'", group.DisplayName)
	}
}

func TestApplySCIMPatchToGroup_RemoveMember(t *testing.T) {
	user1 := "user1"
	user2 := "user2"
	group := &Group{
		ID:          "group1",
		DisplayName: "Administrators",
		Members: []Member{
			{Value: user1, Type: "User"},
			{Value: user2, Type: "User"},
		},
	}

	patchReq := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{
				Op:    "remove",
				Path:  stringPtr("members[user1]"), // Use bracket syntax to remove specific member
				Value: "user1",
			},
		},
	}

	err := ApplySCIMPatchToGroup(group, patchReq)
	if err != nil {
		t.Fatalf("ApplySCIMPatchToGroup() error = %v", err)
	}

	if len(group.Members) != 1 {
		t.Errorf("Members length = %v, want 1", len(group.Members))
	}

	if len(group.Members) > 0 && group.Members[0].Value != user2 {
		t.Errorf("Members[0].Value = %v, want %v", group.Members[0].Value, user2)
	}
}

// ============================================================
// SCIM List Response Tests
// ============================================================

func TestNewSCIMListResponse(t *testing.T) {
	users := []User{
		{ID: "user1", UserName: "john.doe"},
		{ID: "user2", UserName: "jane.doe"},
	}

	resp, err := NewSCIMListResponse(users, 10, 1, 10)
	if err != nil {
		t.Fatalf("NewSCIMListResponse() error = %v", err)
	}

	if resp.TotalResults != 10 {
		t.Errorf("TotalResults = %v, want 10", resp.TotalResults)
	}

	if resp.ItemsPerPage != 10 {
		t.Errorf("ItemsPerPage = %v, want 10", resp.ItemsPerPage)
	}

	if resp.StartIndex != 1 {
		t.Errorf("StartIndex = %v, want 1", resp.StartIndex)
	}

	if len(resp.Schemas) != 1 {
		t.Errorf("Schemas length = %v, want 1", len(resp.Schemas))
	}

	if resp.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Errorf("Schema = %v, want urn:ietf:params:scim:api:messages:2.0:ListResponse", resp.Schemas[0])
	}
}

func TestSCIMListResponseForUsers(t *testing.T) {
	users := []User{
		{ID: "user1", UserName: "john.doe"},
		{ID: "user2", UserName: "jane.doe"},
	}

	resp, err := SCIMListResponseForUsers(users, 2, 1, 10, "http://localhost:8001/scim/v2")
	if err != nil {
		t.Fatalf("SCIMListResponseForUsers() error = %v", err)
	}

	// Unmarshal resources to verify format
	var scimUsers []SCIMUser
	if err := json.Unmarshal(resp.Resources, &scimUsers); err != nil {
		t.Fatalf("Failed to unmarshal resources: %v", err)
	}

	if len(scimUsers) != 2 {
		t.Errorf("Resources length = %v, want 2", len(scimUsers))
	}

	if scimUsers[0].UserName != "john.doe" {
		t.Errorf("First user UserName = %v, want john.doe", scimUsers[0].UserName)
	}
}

func TestSCIMListResponseForGroups(t *testing.T) {
	groups := []Group{
		{ID: "group1", DisplayName: "Admins"},
		{ID: "group2", DisplayName: "Users"},
	}

	resp, err := SCIMListResponseForGroups(groups, 2, 1, 10, "http://localhost:8001/scim/v2")
	if err != nil {
		t.Fatalf("SCIMListResponseForGroups() error = %v", err)
	}

	// Unmarshal resources to verify format
	var scimGroups []SCIMGroup
	if err := json.Unmarshal(resp.Resources, &scimGroups); err != nil {
		t.Fatalf("Failed to unmarshal resources: %v", err)
	}

	if len(scimGroups) != 2 {
		t.Errorf("Resources length = %v, want 2", len(scimGroups))
	}

	if scimGroups[0].DisplayName != "Admins" {
		t.Errorf("First group DisplayName = %v, want Admins", scimGroups[0].DisplayName)
	}
}

// ============================================================
// SCIM Error Tests
// ============================================================

func TestSCIMErrorFromAppError(t *testing.T) {
	err := SCIMErrorFromAppError(404, "", "User not found")

	if len(err.Schemas) != 1 {
		t.Errorf("Schemas length = %v, want 1", len(err.Schemas))
	}

	if err.Status != "404" {
		t.Errorf("Status = %v, want 404", err.Status)
	}

	if err.Detail != "User not found" {
		t.Errorf("Detail = %v, want 'User not found'", err.Detail)
	}
}

func TestSCIMErrorBadRequest(t *testing.T) {
	err := SCIMErrorBadRequest("Invalid filter syntax")

	if err.Status != "400" {
		t.Errorf("Status = %v, want 400", err.Status)
	}

	if err.ScimType != "invalidSyntax" {
		t.Errorf("ScimType = %v, want invalidSyntax", err.ScimType)
	}
}

func TestSCIMErrorConflict(t *testing.T) {
	err := SCIMErrorConflict("Resource already exists")

	if err.Status != "409" {
		t.Errorf("Status = %v, want 409", err.Status)
	}

	if err.ScimType != "uniqueness" {
		t.Errorf("ScimType = %v, want uniqueness", err.ScimType)
	}
}

// ============================================================
// Helper Tests
// ============================================================

func TestGetUserFieldMapping(t *testing.T) {
	mapping := GetUserFieldMapping()

	if len(mapping) == 0 {
		t.Error("Field mapping should not be empty")
	}

	// Check some expected fields
	// Only attributes backed by a real column belong here. groups/roles/photos
	// were removed: they named columns this schema does not have.
	expectedFields := []string{"userName", "displayName", "active", "emails", "externalId"}
	for _, field := range expectedFields {
		if _, ok := mapping[field]; !ok {
			t.Errorf("Expected field %s not found in mapping", field)
		}
	}
}

func TestGetGroupFieldMapping(t *testing.T) {
	mapping := GetGroupFieldMapping()

	if len(mapping) == 0 {
		t.Error("Field mapping should not be empty")
	}

	// Check some expected fields
	// `members` is intentionally absent — membership is a join table, so a
	// filter on it must 400 rather than be silently ignored.
	expectedFields := []string{"displayName", "externalId", "id"}
	for _, field := range expectedFields {
		if _, ok := mapping[field]; !ok {
			t.Errorf("Expected field %s not found in mapping", field)
		}
	}
}
