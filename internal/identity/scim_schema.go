// Package identity provides SCIM 2.0 schema definitions per RFC 7643
package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================
// SCIM 2.0 Resource Types (RFC 7643)
// ============================================================

// SCIMResource is the base interface for all SCIM resources
type SCIMResource interface {
	GetSchemas() []string
	GetID() string
}

// SCIMUser represents a SCIM 2.0 User resource (RFC 7643 4.1)
type SCIMUser struct {
	Schemas           []string          `json:"schemas"`
	ID                string            `json:"id"`
	ExternalID        *string           `json:"externalId,omitempty"`
	UserName          string            `json:"userName"`
	Name              *SCIMName         `json:"name,omitempty"`
	DisplayName       *string           `json:"displayName,omitempty"`
	NickName          *string           `json:"nickName,omitempty"`
	ProfileURL        *string           `json:"profileUrl,omitempty"`
	Title             *string           `json:"title,omitempty"`
	UserType          *string           `json:"userType,omitempty"`
	PreferredLanguage *string           `json:"preferredLanguage,omitempty"`
	Locale            *string           `json:"locale,omitempty"`
	Timezone          *string           `json:"timezone,omitempty"`
	Active            *bool             `json:"active,omitempty"`
	Password          *string           `json:"password,omitempty"`
	Emails            []SCIMEmail       `json:"emails,omitempty"`
	PhoneNumbers      []SCIMPhoneNumber `json:"phoneNumbers,omitempty"`
	Addresses         []SCIMAddress     `json:"addresses,omitempty"`
	Groups            []SCIMGroupRef    `json:"groups,omitempty"`
	Photos            []SCIMPhoto       `json:"photos,omitempty"`
	Entitlements      []SCIMEntitlement `json:"entitlements,omitempty"`
	Roles             []SCIMRole        `json:"roles,omitempty"`
	Meta              *SCIMMeta         `json:"meta,omitempty"`
}

// GetSchemas returns the schemas for this SCIM user
func (u *SCIMUser) GetSchemas() []string {
	if len(u.Schemas) == 0 {
		return []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	}
	return u.Schemas
}

// GetID returns the ID of this SCIM user
func (u *SCIMUser) GetID() string {
	return u.ID
}

// SCIMName represents a user's name in SCIM format
type SCIMName struct {
	GivenName       *string `json:"givenName,omitempty"`
	FamilyName      *string `json:"familyName,omitempty"`
	MiddleName      *string `json:"middleName,omitempty"`
	HonorificPrefix *string `json:"honorificPrefix,omitempty"`
	HonorificSuffix *string `json:"honorificSuffix,omitempty"`
	Formatted       *string `json:"formatted,omitempty"`
}

// SCIMEmail represents an email address in SCIM format
type SCIMEmail struct {
	Value    string  `json:"value"`
	Type     *string `json:"type,omitempty"`
	Primary  *bool   `json:"primary,omitempty"`
	Display  *string `json:"display,omitempty"`
	Verified *bool   `json:"verified,omitempty"`
}

// SCIMPhoneNumber represents a phone number in SCIM format
type SCIMPhoneNumber struct {
	Value   string  `json:"value"`
	Type    *string `json:"type,omitempty"`
	Primary *bool   `json:"primary,omitempty"`
	Display *string `json:"display,omitempty"`
}

// SCIMAddress represents an address in SCIM format
type SCIMAddress struct {
	StreetAddress *string `json:"streetAddress,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postalCode,omitempty"`
	Country       *string `json:"country,omitempty"`
	Formatted     *string `json:"formatted,omitempty"`
	Type          *string `json:"type,omitempty"`
	Primary       *bool   `json:"primary,omitempty"`
}

// SCIMPhoto represents a photo URL in SCIM format
type SCIMPhoto struct {
	Value string  `json:"value"`
	Type  *string `json:"type,omitempty"`
}

// SCIMGroupRef represents a group reference in a user resource
type SCIMGroupRef struct {
	Value   string  `json:"value"`
	Display *string `json:"display,omitempty"`
	Type    string  `json:"type"`
	Ref     *string `json:"$ref,omitempty"`
}

// SCIMEntitlement represents an entitlement in SCIM format
type SCIMEntitlement struct {
	Value string  `json:"value"`
	Type  *string `json:"type,omitempty"`
}

// SCIMRole represents a role in SCIM format
type SCIMRole struct {
	Value string  `json:"value"`
	Type  *string `json:"type,omitempty"`
}

// SCIMMeta represents metadata for a SCIM resource
type SCIMMeta struct {
	ResourceType string     `json:"resourceType"`
	Location     string     `json:"location"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Version      *string    `json:"version,omitempty"`
}

// SCIMGroup represents a SCIM 2.0 Group resource (RFC 7643 4.2)
type SCIMGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	ExternalID  *string      `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	Meta        *SCIMMeta    `json:"meta,omitempty"`
}

// GetSchemas returns the schemas for this SCIM group
func (g *SCIMGroup) GetSchemas() []string {
	if len(g.Schemas) == 0 {
		return []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}
	}
	return g.Schemas
}

// GetID returns the ID of this SCIM group
func (g *SCIMGroup) GetID() string {
	return g.ID
}

// SCIMMember represents a group member in SCIM format
type SCIMMember struct {
	Value   string  `json:"value"`
	Type    string  `json:"type"` // "User" or "Group"
	Display *string `json:"display,omitempty"`
	Ref     *string `json:"$ref,omitempty"`
}

// SCIMListResponse represents a SCIM query response with pagination
//
// The Resources member is capitalized because RFC 7644 §3.4.2 defines it that
// way — it is the one attribute name in the ListResponse that is not
// lowerCamelCase. Emitting "resources" makes strict clients (Okta, Entra ID)
// read an empty page while totalResults says otherwise, which looks like the
// server returning nothing rather than a naming mismatch.
type SCIMListResponse struct {
	Schemas      []string        `json:"schemas"`
	TotalResults int             `json:"totalResults"`
	ItemsPerPage int             `json:"itemsPerPage"`
	StartIndex   int             `json:"startIndex"`
	Resources    json.RawMessage `json:"Resources"`
}

// GetSchemas returns the schemas for the list response
func (r *SCIMListResponse) GetSchemas() []string {
	if len(r.Schemas) == 0 {
		return []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}
	}
	return r.Schemas
}

// SCIMError represents a SCIM error response (RFC 7644 3.12)
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// GetSchemas returns the schemas for the error response
func (e *SCIMError) GetSchemas() []string {
	if len(e.Schemas) == 0 {
		return []string{"urn:ietf:params:scim:api:messages:2.0:Error"}
	}
	return e.Schemas
}

// SCIMPatchOp represents a single patch operation per RFC 7644 3.5.2
type SCIMPatchOp struct {
	Op    string      `json:"op"`             // "add", "replace", "remove"
	Path  *string     `json:"path,omitempty"` // Optional path for multi-valued attributes
	Value interface{} `json:"value,omitempty"`
}

// SCIMPatchRequest represents a SCIM patch request
type SCIMPatchRequest struct {
	Schemas []string      `json:"schemas"`
	Ops     []SCIMPatchOp `json:"Operations"`
}

// ============================================================
// Conversion Functions: SCIM <-> Internal Models
// ============================================================

// UserToSCIM converts an internal User to SCIM 2.0 format
func UserToSCIM(user *User, baseURL string) *SCIMUser {
	if user == nil {
		return nil
	}

	scimUser := &SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       user.ID,
		UserName: user.UserName,
		Active:   &user.Active,
	}

	// External ID
	if user.ExternalID != nil {
		scimUser.ExternalID = user.ExternalID
	}

	// Name
	if user.Name != nil {
		scimUser.Name = &SCIMName{
			GivenName:       user.Name.GivenName,
			FamilyName:      user.Name.FamilyName,
			MiddleName:      user.Name.MiddleName,
			HonorificPrefix: user.Name.HonorificPrefix,
			HonorificSuffix: user.Name.HonorificSuffix,
			Formatted:       user.Name.Formatted,
		}
	}

	// Display Name
	if user.DisplayName != nil {
		scimUser.DisplayName = user.DisplayName
	}

	// Emails
	scimUser.Emails = make([]SCIMEmail, len(user.Emails))
	for i, email := range user.Emails {
		scimUser.Emails[i] = SCIMEmail{
			Value:    email.Value,
			Type:     email.Type,
			Primary:  email.Primary,
			Verified: email.Verified,
		}
	}

	// Phone Numbers
	scimUser.PhoneNumbers = make([]SCIMPhoneNumber, len(user.PhoneNumbers))
	for i, phone := range user.PhoneNumbers {
		scimUser.PhoneNumbers[i] = SCIMPhoneNumber{
			Value:   phone.Value,
			Type:    phone.Type,
			Primary: phone.Primary,
		}
	}

	// Photos
	scimUser.Photos = make([]SCIMPhoto, len(user.Photos))
	for i, photo := range user.Photos {
		scimUser.Photos[i] = SCIMPhoto(photo)
	}

	// Addresses
	scimUser.Addresses = make([]SCIMAddress, len(user.Addresses))
	for i, addr := range user.Addresses {
		scimUser.Addresses[i] = SCIMAddress(addr)
	}

	// Groups
	scimUser.Groups = make([]SCIMGroupRef, len(user.Groups))
	for i, groupID := range user.Groups {
		scimUser.Groups[i] = SCIMGroupRef{
			Value: groupID,
			Type:  "Group",
			Ref:   stringPtr(baseURL + "/Groups/" + groupID),
		}
	}

	// Entitlements
	scimUser.Entitlements = make([]SCIMEntitlement, len(user.Entitlements))
	for i, ent := range user.Entitlements {
		scimUser.Entitlements[i] = SCIMEntitlement{Value: ent}
	}

	// Roles
	scimUser.Roles = make([]SCIMRole, len(user.Roles))
	for i, role := range user.Roles {
		scimUser.Roles[i] = SCIMRole{Value: role}
	}

	// Meta
	if user.Meta != nil {
		scimUser.Meta = &SCIMMeta{
			ResourceType: user.Meta.ResourceType,
			Location:     user.Meta.Location,
			Version:      &user.Meta.Version,
		}
		if !user.Meta.Created.IsZero() {
			scimUser.Meta.Created = &user.Meta.Created
		}
		if !user.Meta.LastModified.IsZero() {
			scimUser.Meta.LastModified = &user.Meta.LastModified
		}
	}

	return scimUser
}

// SCIMToUser converts a SCIM 2.0 User to internal User model
func SCIMToUser(scimUser *SCIMUser) *User {
	if scimUser == nil {
		return nil
	}

	now := time.Now()
	user := &User{
		ID:        scimUser.ID,
		UserName:  scimUser.UserName,
		Active:    true,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Use provided ID or generate new one
	if scimUser.ID == "" {
		user.ID = uuid.New().String()
	}

	// External ID
	if scimUser.ExternalID != nil {
		user.ExternalID = scimUser.ExternalID
	}

	// Active
	if scimUser.Active != nil {
		user.Active = *scimUser.Active
		user.Enabled = *scimUser.Active
	}

	// Display Name
	if scimUser.DisplayName != nil {
		user.DisplayName = scimUser.DisplayName
	}

	// Name
	if scimUser.Name != nil {
		user.Name = &Name{
			GivenName:       scimUser.Name.GivenName,
			FamilyName:      scimUser.Name.FamilyName,
			MiddleName:      scimUser.Name.MiddleName,
			HonorificPrefix: scimUser.Name.HonorificPrefix,
			HonorificSuffix: scimUser.Name.HonorificSuffix,
			Formatted:       scimUser.Name.Formatted,
		}
	}

	// Emails
	if len(scimUser.Emails) > 0 {
		user.Emails = make([]Email, len(scimUser.Emails))
		for i, email := range scimUser.Emails {
			user.Emails[i] = Email(email)
		}
	}

	// Phone Numbers
	if len(scimUser.PhoneNumbers) > 0 {
		user.PhoneNumbers = make([]PhoneNumber, len(scimUser.PhoneNumbers))
		for i, phone := range scimUser.PhoneNumbers {
			user.PhoneNumbers[i] = PhoneNumber{
				Value:   phone.Value,
				Type:    phone.Type,
				Primary: phone.Primary,
			}
		}
	}

	// Photos
	if len(scimUser.Photos) > 0 {
		user.Photos = make([]Photo, len(scimUser.Photos))
		for i, photo := range scimUser.Photos {
			user.Photos[i] = Photo(photo)
		}
	}

	// Addresses
	if len(scimUser.Addresses) > 0 {
		user.Addresses = make([]Address, len(scimUser.Addresses))
		for i, addr := range scimUser.Addresses {
			user.Addresses[i] = Address(addr)
		}
	}

	// Groups
	if len(scimUser.Groups) > 0 {
		user.Groups = make([]string, len(scimUser.Groups))
		for i, group := range scimUser.Groups {
			user.Groups[i] = group.Value
		}
	}

	// Entitlements
	if len(scimUser.Entitlements) > 0 {
		user.Entitlements = make([]string, len(scimUser.Entitlements))
		for i, ent := range scimUser.Entitlements {
			user.Entitlements[i] = ent.Value
		}
	}

	// Roles
	if len(scimUser.Roles) > 0 {
		user.Roles = make([]string, len(scimUser.Roles))
		for i, role := range scimUser.Roles {
			user.Roles[i] = role.Value
		}
	}

	// Meta
	if scimUser.Meta != nil {
		user.Meta = &Meta{
			ResourceType: scimUser.Meta.ResourceType,
			Location:     scimUser.Meta.Location,
			Version:      "1",
		}
		if scimUser.Meta.Created != nil {
			user.Meta.Created = *scimUser.Meta.Created
			user.CreatedAt = *scimUser.Meta.Created
		}
		if scimUser.Meta.LastModified != nil {
			user.Meta.LastModified = *scimUser.Meta.LastModified
			user.UpdatedAt = *scimUser.Meta.LastModified
		}
		if scimUser.Meta.Version != nil {
			user.Meta.Version = *scimUser.Meta.Version
		}
	} else {
		user.Meta = &Meta{
			ResourceType: "User",
			Created:      now,
			LastModified: now,
			Version:      uuid.New().String(),
		}
	}

	return user
}

// GroupToSCIM converts an internal Group to SCIM 2.0 format
func GroupToSCIM(group *Group, baseURL string) *SCIMGroup {
	if group == nil {
		return nil
	}

	scimGroup := &SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          group.ID,
		DisplayName: group.DisplayName,
	}

	// External ID
	if group.ExternalID != nil {
		scimGroup.ExternalID = group.ExternalID
	}

	// Members
	if len(group.Members) > 0 {
		scimGroup.Members = make([]SCIMMember, len(group.Members))
		for i, member := range group.Members {
			scimGroup.Members[i] = SCIMMember{
				Value:   member.Value,
				Type:    member.Type,
				Display: member.Display,
			}
			if member.Ref != nil {
				scimGroup.Members[i].Ref = member.Ref
			} else {
				refURL := baseURL + "/"
				if member.Type == "User" {
					refURL += "Users/"
				} else {
					refURL += "Groups/"
				}
				refURL += member.Value
				scimGroup.Members[i].Ref = &refURL
			}
		}
	}

	// Meta
	if group.Meta != nil {
		scimGroup.Meta = &SCIMMeta{
			ResourceType: group.Meta.ResourceType,
			Location:     group.Meta.Location,
			Version:      &group.Meta.Version,
		}
		if !group.Meta.Created.IsZero() {
			scimGroup.Meta.Created = &group.Meta.Created
		}
		if !group.Meta.LastModified.IsZero() {
			scimGroup.Meta.LastModified = &group.Meta.LastModified
		}
	}

	return scimGroup
}

// SCIMToGroup converts a SCIM 2.0 Group to internal Group model
func SCIMToGroup(scimGroup *SCIMGroup) *Group {
	if scimGroup == nil {
		return nil
	}

	now := time.Now()
	group := &Group{
		ID:          scimGroup.ID,
		DisplayName: scimGroup.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Use provided ID or generate new one
	if scimGroup.ID == "" {
		group.ID = uuid.New().String()
	}

	// External ID
	if scimGroup.ExternalID != nil {
		group.ExternalID = scimGroup.ExternalID
	}

	// Members
	if len(scimGroup.Members) > 0 {
		group.Members = make([]Member, len(scimGroup.Members))
		for i, member := range scimGroup.Members {
			group.Members[i] = Member{
				Value:   member.Value,
				Type:    member.Type,
				Display: member.Display,
				Ref:     member.Ref,
			}
		}
	}

	// Meta
	if scimGroup.Meta != nil {
		group.Meta = &Meta{
			ResourceType: scimGroup.Meta.ResourceType,
			Location:     scimGroup.Meta.Location,
			Version:      "1",
		}
		if scimGroup.Meta.Created != nil {
			group.Meta.Created = *scimGroup.Meta.Created
			group.CreatedAt = *scimGroup.Meta.Created
		}
		if scimGroup.Meta.LastModified != nil {
			group.Meta.LastModified = *scimGroup.Meta.LastModified
			group.UpdatedAt = *scimGroup.Meta.LastModified
		}
		if scimGroup.Meta.Version != nil {
			group.Meta.Version = *scimGroup.Meta.Version
		}
	} else {
		group.Meta = &Meta{
			ResourceType: "Group",
			Created:      now,
			LastModified: now,
			Version:      uuid.New().String(),
		}
	}

	return group
}

// SCIMErrorFromAppError converts an AppError to SCIM error format
func SCIMErrorFromAppError(status int, scimType, detail string) *SCIMError {
	return &SCIMError{
		Schemas:  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:   fmt.Sprintf("%d", status),
		ScimType: scimType,
		Detail:   detail,
	}
}

// SCIMErrorBadRequest creates a 400 Bad Request error
func SCIMErrorBadRequest(detail string) *SCIMError {
	return SCIMErrorFromAppError(400, "invalidSyntax", detail)
}

// SCIMErrorNotFound creates a 404 Not Found error
func SCIMErrorNotFound(detail string) *SCIMError {
	return SCIMErrorFromAppError(404, "", detail)
}

// SCIMErrorConflict creates a 409 Conflict error
func SCIMErrorConflict(detail string) *SCIMError {
	return SCIMErrorFromAppError(409, "uniqueness", detail)
}

// SCIMErrorInternal creates a 500 Internal Server Error
func SCIMErrorInternal(detail string) *SCIMError {
	return SCIMErrorFromAppError(500, "", detail)
}

// ============================================================
// SCIM Pagination Helpers
// ============================================================

// NewSCIMListResponse creates a new SCIM list response with pagination
func NewSCIMListResponse(resources interface{}, totalResults, startIndex, itemsPerPage int) (*SCIMListResponse, error) {
	// Marshal resources to JSON
	resourcesJSON, err := json.Marshal(resources)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resources: %w", err)
	}

	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: totalResults,
		ItemsPerPage: itemsPerPage,
		StartIndex:   startIndex,
		Resources:    resourcesJSON,
	}, nil
}

// SCIMListResponseForUsers creates a SCIM list response for users
func SCIMListResponseForUsers(users []User, totalResults, startIndex, itemsPerPage int, baseURL string) (*SCIMListResponse, error) {
	scimUsers := make([]*SCIMUser, len(users))
	for i := range users {
		scimUsers[i] = UserToSCIM(&users[i], baseURL)
	}
	return NewSCIMListResponse(scimUsers, totalResults, startIndex, itemsPerPage)
}

// SCIMListResponseForGroups creates a SCIM list response for groups
func SCIMListResponseForGroups(groups []Group, totalResults, startIndex, itemsPerPage int, baseURL string) (*SCIMListResponse, error) {
	scimGroups := make([]*SCIMGroup, len(groups))
	for i := range groups {
		scimGroups[i] = GroupToSCIM(&groups[i], baseURL)
	}
	return NewSCIMListResponse(scimGroups, totalResults, startIndex, itemsPerPage)
}

// ============================================================
// SCIM Patch Operation Helpers
// ============================================================

// ApplySCIMPatchToUser applies SCIM patch operations to a User.
//
// Filtered paths are honored for `emails`, the one multi-valued User attribute
// this directory actually stores (`users.email`). They are deliberately NOT
// honored for phoneNumbers, roles, addresses or photos: nothing persists those,
// so "applying" a filtered patch to them would produce an in-memory change that
// UpdateUser discards — a 200 for work that never reached disk. A filtered path
// against one of those is rejected as an unsupported path instead.
//
// Their unfiltered forms are left as they were (accepted, then ignored on
// write). That is the behavior every deployed connector has been running
// against, and RFC 7643 §7 lets a provider ignore attributes outside its
// schema; turning it into a hard 400 would fail whole PATCH requests whose
// name/email operations are perfectly valid. Closing that gap means storing the
// attributes, which is a schema change, not a patch-parser change.
//
// `groups` is different again: it is a real relationship, but RFC 7643 §4.1.2
// makes User.groups readOnly. Membership is changed through the Group resource,
// which now writes it for real — see scim_members.go.
func ApplySCIMPatchToUser(user *User, patchReq *SCIMPatchRequest) error {
	for _, op := range patchReq.Ops {
		switch op.Op {
		case "add":
			if err := applyAddOp(user, op); err != nil {
				return err
			}
		case "replace":
			if err := applyReplaceOp(user, op); err != nil {
				return err
			}
		case "remove":
			if err := applyRemoveOp(user, op); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid patch operation: %s", op.Op)
		}
	}
	return nil
}

// ApplySCIMPatchToGroup applies SCIM patch operations to a Group
func ApplySCIMPatchToGroup(group *Group, patchReq *SCIMPatchRequest) error {
	for _, op := range patchReq.Ops {
		switch op.Op {
		case "add":
			if err := applyGroupAddOp(group, op); err != nil {
				return err
			}
		case "replace":
			if err := applyGroupReplaceOp(group, op); err != nil {
				return err
			}
		case "remove":
			if err := applyGroupRemoveOp(group, op); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid patch operation: %s", op.Op)
		}
	}
	return nil
}

// applyAddOp handles "add" operations for users
func applyAddOp(user *User, op SCIMPatchOp) error {
	if op.Path == nil {
		// Adding to root resource - value must be a full user
		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("value for add without path must be a user object")
		}
		return applyUserAddFromMap(user, valueMap)
	}

	path := *op.Path

	// A filtered path (emails[type eq "work"].value) selects one element of a
	// multi-valued attribute. Handle it before the plain-path switch, which
	// would otherwise fall through to a default branch that matches nothing
	// and returns success without touching the user.
	parsed, err := parseSCIMPatchPath(path)
	if err != nil {
		return err
	}
	if handled, err := applyFilteredUserPatch(user, parsed, op.Value); handled {
		return err
	}
	if parsed.HasFilter() {
		return invalidPathf("unsupported filtered patch path: %s", path)
	}

	switch {
	case path == "emails":
		emails, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("emails value must be an array")
		}
		for _, e := range emails {
			emailMap, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if value, ok := emailMap["value"].(string); ok {
				user.Emails = append(user.Emails, Email{Value: value})
			}
		}
	case path == "phoneNumbers":
		phones, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("phoneNumbers value must be an array")
		}
		for _, p := range phones {
			phoneMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if value, ok := phoneMap["value"].(string); ok {
				user.PhoneNumbers = append(user.PhoneNumbers, PhoneNumber{Value: value})
			}
		}
	case path == "groups":
		groups, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("groups value must be an array")
		}
		for _, g := range groups {
			if groupID, ok := g.(string); ok {
				user.Groups = append(user.Groups, groupID)
			} else if groupMap, ok := g.(map[string]interface{}); ok {
				if value, ok := groupMap["value"].(string); ok {
					user.Groups = append(user.Groups, value)
				}
			}
		}
	case path == "roles":
		roles, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("roles value must be an array")
		}
		for _, r := range roles {
			if role, ok := r.(string); ok {
				user.Roles = append(user.Roles, role)
			} else if roleMap, ok := r.(map[string]interface{}); ok {
				if value, ok := roleMap["value"].(string); ok {
					user.Roles = append(user.Roles, value)
				}
			}
		}
	case strings.HasPrefix(path, "name."):
		// Handle name fields
		if user.Name == nil {
			user.Name = &Name{}
		}
		field := strings.TrimPrefix(path, "name.")
		if value, ok := op.Value.(string); ok {
			switch field {
			case "givenName":
				user.Name.GivenName = &value
			case "familyName":
				user.Name.FamilyName = &value
			case "middleName":
				user.Name.MiddleName = &value
			case "formatted":
				user.Name.Formatted = &value
			}
		}
	default:
		// Handle simple attributes
		if value, ok := op.Value.(string); ok {
			switch path {
			case "displayName":
				user.DisplayName = &value
			case "userName":
				user.UserName = value
			}
		}
		if value, ok := op.Value.(bool); ok {
			switch path {
			case "active":
				user.Active = value
				user.Enabled = value
			}
		}
	}

	return nil
}

// applyReplaceOp handles "replace" operations for users
func applyReplaceOp(user *User, op SCIMPatchOp) error {
	if op.Path == nil {
		// Replace entire user
		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("value for replace without path must be a user object")
		}
		return applyUserAddFromMap(user, valueMap)
	}

	path := *op.Path

	// Same as add: a filtered path targets one element, not the whole array.
	parsed, err := parseSCIMPatchPath(path)
	if err != nil {
		return err
	}
	if handled, err := applyFilteredUserPatch(user, parsed, op.Value); handled {
		return err
	}
	if parsed.HasFilter() {
		return invalidPathf("unsupported filtered patch path: %s", path)
	}

	switch {
	case path == "emails":
		emails, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("emails value must be an array")
		}
		user.Emails = nil
		for _, e := range emails {
			emailMap, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			email := Email{}
			if value, ok := emailMap["value"].(string); ok {
				email.Value = value
			}
			if v, ok := emailMap["type"].(string); ok {
				email.Type = &v
			}
			if v, ok := emailMap["primary"].(bool); ok {
				email.Primary = &v
			}
			if v, ok := emailMap["verified"].(bool); ok {
				email.Verified = &v
			}
			user.Emails = append(user.Emails, email)
		}
	case path == "phoneNumbers":
		phones, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("phoneNumbers value must be an array")
		}
		user.PhoneNumbers = nil
		for _, p := range phones {
			phoneMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			phone := PhoneNumber{}
			if value, ok := phoneMap["value"].(string); ok {
				phone.Value = value
			}
			if v, ok := phoneMap["type"].(string); ok {
				phone.Type = &v
			}
			if v, ok := phoneMap["primary"].(bool); ok {
				phone.Primary = &v
			}
			user.PhoneNumbers = append(user.PhoneNumbers, phone)
		}
	case path == "groups":
		groups, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("groups value must be an array")
		}
		user.Groups = nil
		for _, g := range groups {
			if groupID, ok := g.(string); ok {
				user.Groups = append(user.Groups, groupID)
			} else if groupMap, ok := g.(map[string]interface{}); ok {
				if value, ok := groupMap["value"].(string); ok {
					user.Groups = append(user.Groups, value)
				}
			}
		}
	case path == "roles":
		roles, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("roles value must be an array")
		}
		user.Roles = nil
		for _, r := range roles {
			if role, ok := r.(string); ok {
				user.Roles = append(user.Roles, role)
			} else if roleMap, ok := r.(map[string]interface{}); ok {
				if value, ok := roleMap["value"].(string); ok {
					user.Roles = append(user.Roles, value)
				}
			}
		}
	case strings.HasPrefix(path, "name."):
		if user.Name == nil {
			user.Name = &Name{}
		}
		field := strings.TrimPrefix(path, "name.")
		if value, ok := op.Value.(string); ok {
			switch field {
			case "givenName":
				user.Name.GivenName = &value
			case "familyName":
				user.Name.FamilyName = &value
			case "middleName":
				user.Name.MiddleName = &value
			case "formatted":
				user.Name.Formatted = &value
			}
		}
	default:
		if value, ok := op.Value.(string); ok {
			switch path {
			case "displayName":
				user.DisplayName = &value
			case "userName":
				user.UserName = value
			}
		}
		if value, ok := op.Value.(bool); ok {
			switch path {
			case "active":
				user.Active = value
				user.Enabled = value
			}
		}
	}

	return nil
}

// applyRemoveOp handles "remove" operations for users
func applyRemoveOp(user *User, op SCIMPatchOp) error {
	if op.Path == nil {
		return fmt.Errorf("remove operation requires a path")
	}

	path := *op.Path

	// A filtered remove targets specific elements. The old bracket handling
	// ignored the filter entirely and matched on op.Value, so
	// `emails[type eq "work"]` (which carries no value) removed nothing and
	// still reported success.
	parsed, err := parseSCIMPatchPath(path)
	if err != nil {
		return err
	}
	if handled, err := removeFilteredUserPatch(user, parsed); handled {
		return err
	}
	if parsed.HasFilter() {
		return invalidPathf("unsupported filtered patch path: %s", path)
	}

	// The emails[/phoneNumbers[/groups[/roles[ branches that used to live in
	// this switch are gone: they ignored the filter expression and matched on
	// op.Value, so `emails[type eq "work"]` removed nothing and still reported
	// success. Filtered paths are parsed and applied above.
	switch path {
	case "emails":
		user.Emails = nil
	case "phoneNumbers":
		user.PhoneNumbers = nil
	case "groups":
		user.Groups = nil
	case "roles":
		user.Roles = nil
	case "displayName":
		user.DisplayName = nil
	case "name":
		user.Name = nil
	default:
		// RFC 7644 §3.5.2: an unrecognized path is invalidPath, not a no-op.
		// Returning nil here is how `remove` on a filtered path used to report
		// success without removing anything.
		if strings.HasPrefix(path, "name.") {
			field := strings.TrimPrefix(path, "name.")
			switch field {
			case "givenName", "familyName", "middleName", "formatted":
			default:
				return invalidPathf("unsupported patch path for user remove: %s", path)
			}
			if user.Name == nil {
				return nil
			}
			switch field {
			case "givenName":
				user.Name.GivenName = nil
			case "familyName":
				user.Name.FamilyName = nil
			case "middleName":
				user.Name.MiddleName = nil
			case "formatted":
				user.Name.Formatted = nil
			}
			return nil
		}
		return invalidPathf("unsupported patch path for user remove: %s", path)
	}

	return nil
}

// applyGroupAddOp handles "add" operations for groups
func applyGroupAddOp(group *Group, op SCIMPatchOp) error {
	if op.Path != nil {
		parsed, err := parseSCIMPatchPath(*op.Path)
		if err != nil {
			return err
		}
		if parsed.HasFilter() {
			// `add` appends; selecting an existing element with a filter is not
			// something we can honor, and answering 200 would be a lie.
			return invalidPathf("unsupported filtered patch path: %s", *op.Path)
		}
	}

	if op.Path == nil || *op.Path == "members" {
		members, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("members value must be an array")
		}
		for _, m := range members {
			memberMap, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			member := Member{}
			if value, ok := memberMap["value"].(string); ok {
				member.Value = value
			}
			if v, ok := memberMap["type"].(string); ok {
				member.Type = v
			} else {
				member.Type = "User"
			}
			if v, ok := memberMap["display"].(string); ok {
				member.Display = &v
			}
			// Check for duplicate
			exists := false
			for _, existing := range group.Members {
				if existing.Value == member.Value {
					exists = true
					break
				}
			}
			if !exists {
				group.Members = append(group.Members, member)
			}
		}
	}
	return nil
}

// applyGroupReplaceOp handles "replace" operations for groups
func applyGroupReplaceOp(group *Group, op SCIMPatchOp) error {
	if op.Path == nil {
		// Replace entire group
		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("value for replace without path must be a group object")
		}
		if displayName, ok := valueMap["displayName"].(string); ok {
			group.DisplayName = displayName
		}
		return nil
	}

	parsed, err := parseSCIMPatchPath(*op.Path)
	if err != nil {
		return err
	}
	if handled, err := replaceFilteredGroupMembers(group, parsed, op.Value); handled {
		return err
	}
	if parsed.HasFilter() {
		return invalidPathf("unsupported filtered patch path: %s", *op.Path)
	}

	switch *op.Path {
	case "displayName":
		if value, ok := op.Value.(string); ok {
			group.DisplayName = value
		}
	case "members":
		members, ok := op.Value.([]interface{})
		if !ok {
			return fmt.Errorf("members value must be an array")
		}
		group.Members = nil
		for _, m := range members {
			memberMap, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			member := Member{}
			if value, ok := memberMap["value"].(string); ok {
				member.Value = value
			}
			if v, ok := memberMap["type"].(string); ok {
				member.Type = v
			} else {
				member.Type = "User"
			}
			if v, ok := memberMap["display"].(string); ok {
				member.Display = &v
			}
			group.Members = append(group.Members, member)
		}
	}

	return nil
}

// applyGroupRemoveOp handles "remove" operations for groups
func applyGroupRemoveOp(group *Group, op SCIMPatchOp) error {
	if op.Path == nil {
		return fmt.Errorf("remove operation requires a path")
	}

	// members[value eq "..."] — the form Okta and Entra use to detach one
	// member. The old branch here ignored the filter and matched on op.Value,
	// so a remove expressed purely in the path removed nothing.
	parsed, err := parseSCIMPatchPath(*op.Path)
	if err != nil {
		return err
	}
	if handled, err := removeFilteredGroupMembers(group, parsed); handled {
		return err
	}

	switch *op.Path {
	case "members":
		group.Members = nil
	default:
		return invalidPathf("unsupported patch path for group remove: %s", *op.Path)
	}

	return nil
}

// applyUserAddFromMap applies user fields from a map
func applyUserAddFromMap(user *User, valueMap map[string]interface{}) error {
	for key, value := range valueMap {
		switch key {
		case "userName":
			if v, ok := value.(string); ok {
				user.UserName = v
			}
		case "displayName":
			if v, ok := value.(string); ok {
				user.DisplayName = &v
			}
		case "active":
			if v, ok := value.(bool); ok {
				user.Active = v
				user.Enabled = v
			}
		case "name":
			if nameMap, ok := value.(map[string]interface{}); ok {
				if user.Name == nil {
					user.Name = &Name{}
				}
				if v, ok := nameMap["givenName"].(string); ok {
					user.Name.GivenName = &v
				}
				if v, ok := nameMap["familyName"].(string); ok {
					user.Name.FamilyName = &v
				}
				if v, ok := nameMap["middleName"].(string); ok {
					user.Name.MiddleName = &v
				}
				if v, ok := nameMap["formatted"].(string); ok {
					user.Name.Formatted = &v
				}
			}
		case "emails":
			if emails, ok := value.([]interface{}); ok {
				for _, e := range emails {
					if emailMap, ok := e.(map[string]interface{}); ok {
						email := Email{}
						if v, ok := emailMap["value"].(string); ok {
							email.Value = v
						}
						if v, ok := emailMap["type"].(string); ok {
							email.Type = &v
						}
						if v, ok := emailMap["primary"].(bool); ok {
							email.Primary = &v
						}
						if v, ok := emailMap["verified"].(bool); ok {
							email.Verified = &v
						}
						user.Emails = append(user.Emails, email)
					}
				}
			}
		case "phoneNumbers":
			if phones, ok := value.([]interface{}); ok {
				for _, p := range phones {
					if phoneMap, ok := p.(map[string]interface{}); ok {
						phone := PhoneNumber{}
						if v, ok := phoneMap["value"].(string); ok {
							phone.Value = v
						}
						if v, ok := phoneMap["type"].(string); ok {
							phone.Type = &v
						}
						if v, ok := phoneMap["primary"].(bool); ok {
							phone.Primary = &v
						}
						user.PhoneNumbers = append(user.PhoneNumbers, phone)
					}
				}
			}
		case "groups":
			if groups, ok := value.([]interface{}); ok {
				for _, g := range groups {
					if groupID, ok := g.(string); ok {
						user.Groups = append(user.Groups, groupID)
					} else if groupMap, ok := g.(map[string]interface{}); ok {
						if v, ok := groupMap["value"].(string); ok {
							user.Groups = append(user.Groups, v)
						}
					}
				}
			}
		case "roles":
			if roles, ok := value.([]interface{}); ok {
				for _, r := range roles {
					if role, ok := r.(string); ok {
						user.Roles = append(user.Roles, role)
					} else if roleMap, ok := r.(map[string]interface{}); ok {
						if v, ok := roleMap["value"].(string); ok {
							user.Roles = append(user.Roles, v)
						}
					}
				}
			}
		}
	}
	return nil
}
