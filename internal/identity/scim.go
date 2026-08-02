// Package identity provides SCIM 2.0 HTTP endpoints per RFC 7644
package identity

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ============================================================
// SCIM Route Registration
// ============================================================

// RegisterSCIMRoutes registers SCIM 2.0 endpoints with the Gin router
func (s *Service) RegisterSCIMRoutes(r gin.IRouter) {
	// Bearer token authentication is handled by middleware before these routes

	// User endpoints (RFC 7644 Section 3.3)
	scimUsers := r.Group("/scim/v2/Users")
	{
		scimUsers.GET("", s.HandleSCIMListUsers)
		scimUsers.POST("", s.HandleSCIMCreateUser)
		scimUsers.GET("/:id", s.HandleSCIMGetUser)
		scimUsers.PUT("/:id", s.HandleSCIMReplaceUser)
		scimUsers.PATCH("/:id", s.HandleSCIMPatchUser)
		scimUsers.DELETE("/:id", s.HandleSCIMDeleteUser)
	}

	// Group endpoints (RFC 7644 Section 3.3)
	scimGroups := r.Group("/scim/v2/Groups")
	{
		scimGroups.GET("", s.HandleSCIMListGroups)
		scimGroups.POST("", s.HandleSCIMCreateGroup)
		scimGroups.GET("/:id", s.HandleSCIMGetGroup)
		scimGroups.PUT("/:id", s.HandleSCIMReplaceGroup)
		scimGroups.PATCH("/:id", s.HandleSCIMPatchGroup)
		scimGroups.DELETE("/:id", s.HandleSCIMDeleteGroup)
	}

	// Service Provider Config endpoint (RFC 7644 Section 4)
	r.GET("/scim/v2/ServiceProviderConfig", s.HandleSCIMServiceProviderConfig)
	r.GET("/scim/v2/ResourceTypes", s.HandleSCIMResourceTypes)
	r.GET("/scim/v2/Schemas", s.HandleSCIMSchemas)

	// Discovery endpoint (RFC 7643 Section 4)
	r.GET("/scim/v2", s.HandleSCIMDiscovery)
}

// ============================================================
// SCIM User Endpoints
// ============================================================

// HandleSCIMListUsers handles GET /scim/v2/Users with filtering and pagination
// Implements RFC 7644 Section 3.4.1
func (s *Service) HandleSCIMListUsers(c *gin.Context) {
	// Parse query parameters
	startIndex := s.parseSCIMStartIndex(c)
	count := s.parseSCIMCount(c)
	filterStr := c.Query("filter")

	// Build base filter
	baseFilter := UserFilter{
		PaginationParams: PaginationParams{
			Offset: startIndex - 1, // SCIM is 1-indexed
			Limit:  count,
		},
	}

	// Parse the SCIM filter and convert it to a SQL predicate.
	//
	// Placeholders start at $2 because the query below spends $1 on the tenant
	// id. An unsupported attribute fails here and becomes a 400 rather than
	// being dropped — the old code logged the clause and discarded it, so every
	// filtered request returned the tenant's whole user list while
	// ServiceProviderConfig advertised filter support.
	var sqlFilter *SQLFilter
	if filterStr != "" {
		scimFilter, err := ParseFilter(filterStr)
		if err != nil {
			s.logger.Debug("Invalid SCIM filter", zap.String("filter", filterStr), zap.Error(err))
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest(fmt.Sprintf("Invalid filter: %s", err)))
			return
		}

		sqlFilter, err = FilterToSQLFrom(scimFilter, GetUserFieldMapping(), 2)
		if err != nil {
			s.logger.Debug("Failed to convert SCIM filter to SQL", zap.Error(err))
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest(fmt.Sprintf("Unsupported filter: %s", err)))
			return
		}
	}

	// Enforce tenant isolation from Bearer token
	if tenantID, exists := c.Get("tenant_id"); exists {
		tenantIDStr, _ := tenantID.(string)
		baseFilter.OrganizationID = &tenantIDStr
	}

	users, total, err := s.listUsersForSCIM(c.Request.Context(), baseFilter.Offset, baseFilter.Limit, sqlFilter)
	if err != nil {
		s.logger.Error("Failed to list users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve users"))
		return
	}
	// Get base URL for meta.location
	baseURL := s.getSCIMBaseURL(c)

	scimResp, err := SCIMListResponseForUsers(users, total, startIndex, count, baseURL)
	if err != nil {
		s.logger.Error("Failed to create SCIM response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to format response"))
		return
	}

	c.JSON(http.StatusOK, scimResp)
}

// HandleSCIMCreateUser handles POST /scim/v2/Users
// Implements RFC 7644 Section 3.3
func (s *Service) HandleSCIMCreateUser(c *gin.Context) {
	var scimUser SCIMUser
	if err := c.ShouldBindJSON(&scimUser); err != nil {
		s.logger.Debug("Invalid SCIM user JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Validate required fields
	if scimUser.UserName == "" {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("userName is required"))
		return
	}

	// Check for duplicate username
	existing, _ := s.GetUserByUsername(c.Request.Context(), scimUser.UserName)
	if existing != nil {
		c.JSON(http.StatusConflict, SCIMErrorConflict("User already exists"))
		return
	}

	// Check for duplicate email (if provided)
	if len(scimUser.Emails) > 0 && scimUser.Emails[0].Value != "" {
		existing, _ = s.GetUserByEmail(c.Request.Context(), scimUser.Emails[0].Value)
		if existing != nil {
			c.JSON(http.StatusConflict, SCIMErrorConflict("User with this email already exists"))
			return
		}
	}

	// Convert to internal User model
	user := SCIMToUser(&scimUser)

	// Set tenant context
	if tenantID, exists := c.Get("tenant_id"); exists {
		tenantIDStr, _ := tenantID.(string)
		user.OrganizationID = &tenantIDStr
	}

	// Create user
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.CreateUser(ctx, user); err != nil {
		s.logger.Error("Failed to create SCIM user",
			zap.String("username", scimUser.UserName),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to create user"))
		return
	}

	// Convert back to SCIM with generated ID and metadata
	baseURL := s.getSCIMBaseURL(c)
	user.UpdateMeta(baseURL + "/scim/v2")
	responseUser := UserToSCIM(user, baseURL+"/scim/v2")

	c.JSON(http.StatusCreated, responseUser)
}

// HandleSCIMGetUser handles GET /scim/v2/Users/:id
// Implements RFC 7644 Section 3.4.1
func (s *Service) HandleSCIMGetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("User not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, user.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	scimUser := UserToSCIM(user, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, scimUser)
}

// HandleSCIMReplaceUser handles PUT /scim/v2/Users/:id
// Implements RFC 7644 Section 3.5.1
func (s *Service) HandleSCIMReplaceUser(c *gin.Context) {
	userID := c.Param("id")

	var scimUser SCIMUser
	if err := c.ShouldBindJSON(&scimUser); err != nil {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Get existing user
	existing, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("User not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, existing.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	// Validate userName uniqueness if changed
	if scimUser.UserName != existing.UserName && scimUser.UserName != "" {
		duplicate, _ := s.GetUserByUsername(c.Request.Context(), scimUser.UserName)
		if duplicate != nil && duplicate.ID != userID {
			c.JSON(http.StatusConflict, SCIMErrorConflict("Username already exists"))
			return
		}
	}

	// Convert SCIM user to internal model
	user := SCIMToUser(&scimUser)
	user.ID = userID
	user.CreatedAt = existing.CreatedAt
	user.OrganizationID = existing.OrganizationID

	// Update user
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateUser(ctx, user); err != nil {
		s.logger.Error("Failed to update SCIM user", zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to update user"))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	user.UpdateMeta(baseURL + "/scim/v2")
	responseUser := UserToSCIM(user, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, responseUser)
}

// HandleSCIMPatchUser handles PATCH /scim/v2/Users/:id
// Implements RFC 7644 Section 3.5.2
func (s *Service) HandleSCIMPatchUser(c *gin.Context) {
	userID := c.Param("id")

	var patchReq SCIMPatchRequest
	if err := c.ShouldBindJSON(&patchReq); err != nil {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Validate schemas
	if len(patchReq.Schemas) > 0 {
		hasPatchSchema := false
		for _, schema := range patchReq.Schemas {
			if schema == "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
				hasPatchSchema = true
				break
			}
		}
		if !hasPatchSchema {
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid schema for PATCH request"))
			return
		}
	}

	// Get existing user
	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("User not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, user.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	// Apply patch operations
	if err := ApplySCIMPatchToUser(user, &patchReq); err != nil {
		s.logger.Debug("Failed to apply SCIM patch", zap.Error(err))
		c.JSON(http.StatusBadRequest, SCIMErrorFromAppError(
			http.StatusBadRequest, scimPatchErrorType(err), fmt.Sprintf("Invalid patch: %s", err)))
		return
	}

	// Update user
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateUser(ctx, user); err != nil {
		s.logger.Error("Failed to apply SCIM patch", zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to update user"))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	user.UpdateMeta(baseURL + "/scim/v2")
	responseUser := UserToSCIM(user, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, responseUser)
}

// HandleSCIMDeleteUser handles DELETE /scim/v2/Users/:id
// Implements RFC 7644 Section 3.6
func (s *Service) HandleSCIMDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	// Get existing user first for tenant check
	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("User not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, user.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.DeleteUser(ctx, userID); err != nil {
		s.logger.Error("Failed to delete SCIM user", zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to delete user"))
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================
// SCIM Group Endpoints
// ============================================================

// HandleSCIMListGroups handles GET /scim/v2/Groups with filtering and pagination
func (s *Service) HandleSCIMListGroups(c *gin.Context) {
	// Parse query parameters
	startIndex := s.parseSCIMStartIndex(c)
	count := s.parseSCIMCount(c)
	filterStr := c.Query("filter")

	// Build base filter
	baseFilter := GroupFilter{
		PaginationParams: PaginationParams{
			Offset: startIndex - 1,
			Limit:  count,
		},
	}

	// Same as the Users handler: the converted predicate is applied, not logged
	// and dropped. Placeholders start at $2 because $1 is the tenant id.
	var sqlFilter *SQLFilter
	if filterStr != "" {
		scimFilter, err := ParseFilter(filterStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest(fmt.Sprintf("Invalid filter: %s", err)))
			return
		}

		sqlFilter, err = FilterToSQLFrom(scimFilter, GetGroupFieldMapping(), 2)
		if err != nil {
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest(fmt.Sprintf("Unsupported filter: %s", err)))
			return
		}
	}

	// Enforce tenant isolation
	if tenantID, exists := c.Get("tenant_id"); exists {
		tenantIDStr, _ := tenantID.(string)
		baseFilter.OrganizationID = &tenantIDStr
	}

	groups, total, err := s.listGroupsForSCIM(c.Request.Context(), baseFilter.Offset, baseFilter.Limit, sqlFilter)
	if err != nil {
		s.logger.Error("Failed to list groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve groups"))
		return
	}

	// One batched query for the whole page — see loadGroupMembers on why an
	// empty roster is worse than no answer at all.
	if err := s.loadMembersForGroups(c.Request.Context(), groups); err != nil {
		s.logger.Error("Failed to load group members", zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve group members"))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	scimResp, err := SCIMListResponseForGroups(groups, total, startIndex, count, baseURL+"/scim/v2")
	if err != nil {
		s.logger.Error("Failed to create SCIM response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to format response"))
		return
	}

	c.JSON(http.StatusOK, scimResp)
}

// HandleSCIMCreateGroup handles POST /scim/v2/Groups
func (s *Service) HandleSCIMCreateGroup(c *gin.Context) {
	var scimGroup SCIMGroup
	if err := c.ShouldBindJSON(&scimGroup); err != nil {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Validate required fields
	if scimGroup.DisplayName == "" {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("displayName is required"))
		return
	}

	// Check for duplicate group name
	existing, _ := s.GetGroupByDisplayName(c.Request.Context(), scimGroup.DisplayName)
	if existing != nil {
		c.JSON(http.StatusConflict, SCIMErrorConflict("Group already exists"))
		return
	}

	// Convert to internal Group model
	group := SCIMToGroup(&scimGroup)

	// Set tenant context
	if tenantID, exists := c.Get("tenant_id"); exists {
		tenantIDStr, _ := tenantID.(string)
		group.OrganizationID = &tenantIDStr
	}

	// Create group
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.CreateGroup(ctx, group); err != nil {
		s.logger.Error("Failed to create SCIM group",
			zap.String("display_name", scrubLogValue(scimGroup.DisplayName)),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to create group"))
		return
	}

	// A create that carries members has to write them; returning 201 with the
	// roster echoed back while the membership table stays empty is how a client
	// ends up believing a group is populated when it is not.
	if err := s.syncGroupMembers(ctx, group.ID, nil, group.Members); err != nil {
		status, scimType := scimMemberErrorStatus(err)
		s.logger.Warn("Failed to add members to new SCIM group",
			zap.String("group_id", scrubLogValue(group.ID)), zap.Error(err))
		c.JSON(status, SCIMErrorFromAppError(status, scimType, fmt.Sprintf("Failed to add members: %s", err)))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	group.UpdateMeta(baseURL + "/scim/v2")
	responseGroup := GroupToSCIM(group, baseURL+"/scim/v2")

	c.JSON(http.StatusCreated, responseGroup)
}

// HandleSCIMGetGroup handles GET /scim/v2/Groups/:id
func (s *Service) HandleSCIMGetGroup(c *gin.Context) {
	groupID := c.Param("id")

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("Group not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, group.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	// GetGroup reads the `groups` row only. Without this the response reports
	// every group as empty, which reads to Okta and Entra as "the roster was
	// deleted out from under us" and triggers a full re-push each sync.
	if err := s.loadGroupMembers(c.Request.Context(), group); err != nil {
		s.logger.Error("Failed to load group members", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve group members"))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	scimGroup := GroupToSCIM(group, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, scimGroup)
}

// HandleSCIMReplaceGroup handles PUT /scim/v2/Groups/:id
func (s *Service) HandleSCIMReplaceGroup(c *gin.Context) {
	groupID := c.Param("id")

	var scimGroup SCIMGroup
	if err := c.ShouldBindJSON(&scimGroup); err != nil {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Get existing group
	existing, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("Group not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, existing.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	// Validate displayName uniqueness if changed
	if scimGroup.DisplayName != existing.DisplayName && scimGroup.DisplayName != "" {
		duplicate, _ := s.GetGroupByDisplayName(c.Request.Context(), scimGroup.DisplayName)
		if duplicate != nil && duplicate.ID != groupID {
			c.JSON(http.StatusConflict, SCIMErrorConflict("Group name already exists"))
			return
		}
	}

	// Convert SCIM group to internal model
	group := SCIMToGroup(&scimGroup)
	group.ID = groupID
	group.CreatedAt = existing.CreatedAt
	group.OrganizationID = existing.OrganizationID

	// Update group
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateGroup(ctx, group); err != nil {
		s.logger.Error("Failed to update SCIM group", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to update group"))
		return
	}

	// PUT replaces the resource, members included (RFC 7644 §3.5.1), so the
	// roster in the body is authoritative: anyone absent from it is removed.
	if err := s.loadGroupMembers(c.Request.Context(), existing); err != nil {
		s.logger.Error("Failed to load group members", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve group members"))
		return
	}
	if err := s.syncGroupMembers(ctx, groupID, existing.Members, group.Members); err != nil {
		status, scimType := scimMemberErrorStatus(err)
		s.logger.Warn("Failed to sync SCIM group members", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(status, SCIMErrorFromAppError(status, scimType, fmt.Sprintf("Failed to update members: %s", err)))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	group.UpdateMeta(baseURL + "/scim/v2")
	responseGroup := GroupToSCIM(group, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, responseGroup)
}

// HandleSCIMPatchGroup handles PATCH /scim/v2/Groups/:id
func (s *Service) HandleSCIMPatchGroup(c *gin.Context) {
	groupID := c.Param("id")

	var patchReq SCIMPatchRequest
	if err := c.ShouldBindJSON(&patchReq); err != nil {
		c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid request body"))
		return
	}

	// Validate schemas
	if len(patchReq.Schemas) > 0 {
		hasPatchSchema := false
		for _, schema := range patchReq.Schemas {
			if schema == "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
				hasPatchSchema = true
				break
			}
		}
		if !hasPatchSchema {
			c.JSON(http.StatusBadRequest, SCIMErrorBadRequest("Invalid schema for PATCH request"))
			return
		}
	}

	// Get existing group
	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("Group not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, group.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	// Load the real roster before patching. Without this the patch is applied
	// to an empty Members slice: `add` appends to nothing and is discarded,
	// and a filtered `remove` finds no target.
	if err := s.loadGroupMembers(c.Request.Context(), group); err != nil {
		s.logger.Error("Failed to load group members", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to retrieve group members"))
		return
	}
	before := append([]Member(nil), group.Members...)

	// Apply patch operations
	if err := ApplySCIMPatchToGroup(group, &patchReq); err != nil {
		s.logger.Debug("Failed to apply SCIM group patch", zap.Error(err))
		c.JSON(http.StatusBadRequest, SCIMErrorFromAppError(
			http.StatusBadRequest, scimPatchErrorType(err), fmt.Sprintf("Invalid patch: %s", err)))
		return
	}

	// Update group
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateGroup(ctx, group); err != nil {
		s.logger.Error("Failed to apply SCIM patch", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to update group"))
		return
	}

	// Membership lives in group_memberships, which UpdateGroup does not touch —
	// so the roster change has to be written here or the 200 below would be
	// reporting a membership that does not exist.
	if err := s.syncGroupMembers(ctx, groupID, before, group.Members); err != nil {
		status, scimType := scimMemberErrorStatus(err)
		s.logger.Warn("Failed to sync SCIM group members", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(status, SCIMErrorFromAppError(status, scimType, fmt.Sprintf("Failed to update members: %s", err)))
		return
	}

	baseURL := s.getSCIMBaseURL(c)
	group.UpdateMeta(baseURL + "/scim/v2")
	responseGroup := GroupToSCIM(group, baseURL+"/scim/v2")

	c.JSON(http.StatusOK, responseGroup)
}

// HandleSCIMDeleteGroup handles DELETE /scim/v2/Groups/:id
func (s *Service) HandleSCIMDeleteGroup(c *gin.Context) {
	groupID := c.Param("id")

	// Get existing group first for tenant check
	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, SCIMErrorNotFound("Group not found"))
		return
	}

	// Enforce tenant isolation
	if !s.checkSCIMTenantAccess(c, group.OrganizationID) {
		c.JSON(http.StatusForbidden, SCIMErrorMap(403, "", "Access denied"))
		return
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.DeleteGroup(ctx, groupID); err != nil {
		s.logger.Error("Failed to delete SCIM group", zap.String("group_id", scrubLogValue(groupID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, SCIMErrorInternal("Failed to delete group"))
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================
// SCIM Discovery and Configuration Endpoints
// ============================================================

// SCIMServiceProviderConfig represents the service provider configuration per RFC 7644
type SCIMServiceProviderConfig struct {
	Schemas               []string                    `json:"schemas"`
	Patch                 *SCIMPatchSupport           `json:"patch"`
	Bulk                  *SCIMBulkSupport            `json:"bulk"`
	Filter                *SCIMFilterSupport          `json:"filter"`
	ChangePassword        *SCIMChangePasswordSupport  `json:"changePassword"`
	Sort                  *SCIMSortSupport            `json:"sort"`
	ETag                  *SCIMETagSupport            `json:"etag"`
	AuthenticationSchemes *[]SCIMAuthenticationScheme `json:"authenticationSchemes,omitempty"`
}

// SCIMPatchSupport describes patch support
type SCIMPatchSupport struct {
	Supported bool `json:"supported"`
}

// SCIMBulkSupport describes bulk support
type SCIMBulkSupport struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// SCIMFilterSupport describes filter support
type SCIMFilterSupport struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// SCIMChangePasswordSupport describes password change support
type SCIMChangePasswordSupport struct {
	Supported bool `json:"supported"`
}

// SCIMSortSupport describes sort support
type SCIMSortSupport struct {
	Supported bool `json:"supported"`
}

// SCIMETagSupport describes ETag support
type SCIMETagSupport struct {
	Supported bool `json:"supported"`
}

// SCIMAuthenticationScheme describes an authentication scheme
type SCIMAuthenticationScheme struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
}

// SCIMResourceType represents a SCIM resource type
type SCIMResourceType struct {
	Schemas          []string              `json:"schemas"`
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Endpoint         string                `json:"endpoint"`
	Description      string                `json:"description"`
	Schema           string                `json:"schema"`
	SchemaExtensions []SCIMSchemaExtension `json:"schemaExtensions,omitempty"`
}

// SCIMSchemaExtension represents a schema extension
type SCIMSchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// SCIMSchema represents a SCIM schema definition
type SCIMSchema struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Attributes  []SCIMSchemaAttr `json:"attributes"`
}

// SCIMSchemaAttr represents a schema attribute
type SCIMSchemaAttr struct {
	Name          string           `json:"name"`
	Type          string           `json:"type"`
	MultiValued   bool             `json:"multiValued"`
	Description   string           `json:"description"`
	Required      bool             `json:"required"`
	CaseExact     bool             `json:"caseExact"`
	Mutability    string           `json:"mutability"`
	Returned      string           `json:"returned"`
	Uniqueness    string           `json:"uniqueness"`
	SubAttributes []SCIMSchemaAttr `json:"subAttributes,omitempty"`
}

// HandleSCIMServiceProviderConfig returns the service provider configuration
// Implements RFC 7644 Section 5
func (s *Service) HandleSCIMServiceProviderConfig(c *gin.Context) {
	authSchemes := []SCIMAuthenticationScheme{
		{
			Name:        "OAuth Bearer Token",
			Description: "Authentication using Bearer Token",
			SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
		},
	}

	config := &SCIMServiceProviderConfig{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		Patch: &SCIMPatchSupport{
			Supported: true,
		},
		Bulk: &SCIMBulkSupport{
			Supported:      false,
			MaxOperations:  0,
			MaxPayloadSize: 0,
		},
		Filter: &SCIMFilterSupport{
			Supported:  true,
			MaxResults: 100,
		},
		ChangePassword: &SCIMChangePasswordSupport{
			Supported: false,
		},
		Sort: &SCIMSortSupport{
			Supported: false,
		},
		ETag: &SCIMETagSupport{
			Supported: true,
		},
		AuthenticationSchemes: &authSchemes,
	}

	c.JSON(http.StatusOK, config)
}

// HandleSCIMResourceTypes returns available resource types
func (s *Service) HandleSCIMResourceTypes(c *gin.Context) {
	baseURL := s.getSCIMBaseURL(c)

	resourceTypes := []map[string]interface{}{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    baseURL + "/scim/v2/Users",
			"description": "User Account",
			"schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    baseURL + "/scim/v2/Groups",
			"description": "Group",
			"schema":      "urn:ietf:params:scim:schemas:core:2.0:Group",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resourceTypes),
		"itemsPerPage": len(resourceTypes),
		"startIndex":   1,
		"Resources":    resourceTypes, // RFC 7644 §3.4.2 capitalizes this member
	})
}

// HandleSCIMSchemas returns available schemas
func (s *Service) HandleSCIMSchemas(c *gin.Context) {
	schemas := []map[string]interface{}{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          "urn:ietf:params:scim:schemas:core:2.0:User",
			"name":        "User",
			"description": "User Account",
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          "urn:ietf:params:scim:schemas:core:2.0:Group",
			"name":        "Group",
			"description": "Group",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(schemas),
		"itemsPerPage": len(schemas),
		"startIndex":   1,
		"Resources":    schemas, // RFC 7644 §3.4.2 capitalizes this member
	})
}

// HandleSCIMDiscovery returns the SCIM service discovery document
func (s *Service) HandleSCIMDiscovery(c *gin.Context) {
	baseURL := s.getSCIMBaseURL(c)

	c.JSON(http.StatusOK, gin.H{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch": gin.H{
			"supported": true,
		},
		"bulk": gin.H{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": gin.H{
			"supported":  true,
			"maxResults": 100,
		},
		"changePassword": gin.H{
			"supported": false,
		},
		"sort": gin.H{
			"supported": false,
		},
		"etag": gin.H{
			"supported": true,
		},
		"authenticationSchemes": []gin.H{
			{
				"name":        "OAuth Bearer Token",
				"description": "Authentication using Bearer Token",
				"specUri":     "http://www.rfc-editor.org/info/rfc6750",
			},
		},
		"location": baseURL + "/scim/v2",
	})
}

// ============================================================
// SCIM Helper Methods
// ============================================================

// parseSCIMStartIndex parses the startIndex query parameter (1-indexed per SCIM spec)
func (s *Service) parseSCIMStartIndex(c *gin.Context) int {
	startIndexStr := c.DefaultQuery("startIndex", "1")
	startIndex, err := strconv.Atoi(startIndexStr)
	if err != nil || startIndex < 1 {
		return 1
	}
	return startIndex
}

// parseSCIMCount parses the count query parameter
func (s *Service) parseSCIMCount(c *gin.Context) int {
	countStr := c.DefaultQuery("count", "100")
	count, err := strconv.Atoi(countStr)
	if err != nil || count < 1 {
		return 100
	}
	if count > 100 {
		// SCIM spec says return 400 if count exceeds server max, but we'll cap at 100
		return 100
	}
	return count
}

// getSCIMBaseURL returns the base URL for SCIM resources
func (s *Service) getSCIMBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	return fmt.Sprintf("%s://%s", scheme, host)
}

// checkSCIMTenantAccess checks if the request has access to the given tenant
func (s *Service) checkSCIMTenantAccess(c *gin.Context, resourceOrgID *string) bool {
	// Get tenant from Bearer token context
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		// No tenant context - allow if resource has no tenant
		return resourceOrgID == nil
	}

	tenantIDStr, _ := tenantID.(string)

	// Admin users can access any tenant
	if roles, exists := c.Get("roles"); exists {
		if roleList, ok := roles.([]string); ok {
			for _, role := range roleList {
				if role == "admin" || role == "superadmin" {
					return true
				}
			}
		}
	}

	// Check if resource belongs to the token's tenant
	if resourceOrgID == nil {
		return true // No tenant association
	}
	return *resourceOrgID == tenantIDStr
}

// ============================================================
// SCIM Bearer Token Authentication Middleware
// ============================================================

// SCIMAuthMiddleware validates Bearer tokens for SCIM endpoints
func SCIMAuthMiddleware(validTokens map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, SCIMErrorMap(401, "", "Missing Authorization header"))
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, SCIMErrorMap(401, "", "Invalid Authorization header format"))
			c.Abort()
			return
		}

		token := parts[1]

		// Validate token
		tenantID, ok := validTokens[token]
		if !ok {
			c.JSON(http.StatusUnauthorized, SCIMErrorMap(401, "", "Invalid Bearer token"))
			c.Abort()
			return
		}

		// Set tenant context for downstream handlers
		c.Set("tenant_id", tenantID)
		c.Set("auth_method", "scim_bearer")
		c.Set("access_type", "scim")

		c.Next()
	}
}

// SCIMErrorMap creates a SCIM error from HTTP status and details
func SCIMErrorMap(status int, scimType, detail string) map[string]interface{} {
	return gin.H{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":   strconv.Itoa(status),
		"scimType": scimType,
		"detail":   detail,
	}
}
