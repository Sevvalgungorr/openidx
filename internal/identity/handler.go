// Package identity provides HTTP handlers for identity CRUD operations
package identity

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// CreateOrUpdateUserRequest represents the request body for creating/updating a user
type CreateOrUpdateUserRequest struct {
	UserName    string   `json:"userName" binding:"required"`
	Email       string   `json:"email" binding:"required,email"`
	FirstName   string   `json:"firstName"`
	LastName    string   `json:"lastName"`
	DisplayName *string  `json:"displayName"`
	Enabled     *bool    `json:"enabled"`
	Roles       []string `json:"roles"`
	Groups      []string `json:"groups"`
}

// ToUser converts the request to a User model
func (r *CreateOrUpdateUserRequest) ToUser() *User {
	user := NewUser(r.UserName)
	user.SetEmail(r.Email)
	user.SetFirstName(r.FirstName)
	user.SetLastName(r.LastName)

	if r.DisplayName != nil {
		user.DisplayName = r.DisplayName
	}
	if r.Enabled != nil {
		// Sync both Enabled (OpenIDX) and Active (SCIM) fields to maintain consistency
		user.Enabled = *r.Enabled
		user.Active = *r.Enabled
	}
	if len(r.Roles) > 0 {
		user.Roles = r.Roles
	}
	if len(r.Groups) > 0 {
		user.Groups = r.Groups
	}

	return user
}

// CreateOrUpdateGroupRequest represents the request body for creating/updating a group
type CreateOrUpdateGroupRequest struct {
	DisplayName string   `json:"displayName" binding:"required"`
	Description *string  `json:"description"`
	Members     []string `json:"members"` // Array of user IDs
}

// ToGroup converts the request to a Group model
func (r *CreateOrUpdateGroupRequest) ToGroup() *Group {
	group := NewGroup(r.DisplayName)

	if r.Description != nil {
		group.SetDescription(*r.Description)
	}

	// Convert member user IDs to Member references
	for _, userID := range r.Members {
		group.Members = append(group.Members, Member{
			Value: userID,
			Type:  "User",
		})
	}

	return group
}

// ListUsersResponse represents the paginated response for listing users
type ListUsersResponse struct {
	Users []User `json:"users"`
	Total int    `json:"total"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

// ListGroupsResponse represents the paginated response for listing groups
type ListGroupsResponse struct {
	Groups []Group `json:"groups"`
	Total  int     `json:"total"`
	Page   int     `json:"page"`
	Limit  int     `json:"limit"`
}

// ============================================================
// User CRUD Handlers
// ============================================================

// HandleCreateUser handles POST /api/v1/users
func (s *Service) HandleCreateUser(c *gin.Context) {
	var req CreateOrUpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.HandleError(c, apperrors.ValidationError("invalid request body: "+err.Error()))
		return
	}

	// Get tenant ID from context for tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	// Validate input
	if err := validateCreateUserRequest(&req); err != nil {
		apperrors.HandleError(c, err)
		return
	}

	// Check for duplicate username
	existing, _ := s.GetUserByUsername(c.Request.Context(), req.UserName)
	if existing != nil {
		apperrors.HandleError(c, apperrors.UserAlreadyExists(req.UserName))
		return
	}

	// Check for duplicate email
	existing, _ = s.GetUserByEmail(c.Request.Context(), req.Email)
	if existing != nil {
		apperrors.HandleError(c, apperrors.Conflict("user with this email already exists"))
		return
	}

	user := req.ToUser()
	tenantIDStr, _ := tenantID.(string)
	user.OrganizationID = &tenantIDStr

	// Create the user with actor context
	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.CreateUser(ctx, user); err != nil {
		s.logger.Error("failed to create user",
			zap.String("username", req.UserName),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("create user", err))
		return
	}

	// Emit lifecycle event
	s.emitUserLifecycleEvent(c.Request.Context(), "user.created", user.ID, actorID)

	c.JSON(http.StatusCreated, user)
}

// HandleGetUser handles GET /api/v1/users/:id
func (s *Service) HandleGetUser(c *gin.Context) {
	userID := c.Param("id")

	// Validate tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleError(c, apperrors.UserNotFound(userID))
		return
	}

	// Enforce tenant isolation
	if user.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *user.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to user from different tenant not allowed"))
			return
		}
	}

	c.JSON(http.StatusOK, user)
}

// HandleUpdateUser handles PUT /api/v1/users/:id
func (s *Service) HandleUpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var req CreateOrUpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.HandleError(c, apperrors.ValidationError("invalid request body: "+err.Error()))
		return
	}

	// Get existing user first to enforce tenant isolation
	existing, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleError(c, apperrors.UserNotFound(userID))
		return
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists && existing.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *existing.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to user from different tenant not allowed"))
			return
		}
	}

	// Check for duplicate username if changed
	if req.UserName != existing.UserName {
		duplicate, _ := s.GetUserByUsername(c.Request.Context(), req.UserName)
		if duplicate != nil && duplicate.ID != userID {
			apperrors.HandleError(c, apperrors.Conflict("username already exists"))
			return
		}
	}

	// Check for duplicate email if changed
	if req.Email != existing.GetEmail() {
		duplicate, _ := s.GetUserByEmail(c.Request.Context(), req.Email)
		if duplicate != nil && duplicate.ID != userID {
			apperrors.HandleError(c, apperrors.Conflict("email already exists"))
			return
		}
	}

	// Update user with request data
	user := req.ToUser()
	user.ID = userID
	user.CreatedAt = existing.CreatedAt // Preserve creation timestamp
	if existing.OrganizationID != nil {
		user.OrganizationID = existing.OrganizationID
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateUser(ctx, user); err != nil {
		s.logger.Error("failed to update user",
			zap.String("user_id", userID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("update user", err))
		return
	}

	// Emit lifecycle event
	s.emitUserLifecycleEvent(c.Request.Context(), "user.updated", user.ID, actorID)

	c.JSON(http.StatusOK, user)
}

// HandleDeleteUser handles DELETE /api/v1/users/:id
func (s *Service) HandleDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	// Get existing user first to enforce tenant isolation
	existing, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleError(c, apperrors.UserNotFound(userID))
		return
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists && existing.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *existing.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to user from different tenant not allowed"))
			return
		}
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.DeleteUser(ctx, userID); err != nil {
		s.logger.Error("failed to delete user",
			zap.String("user_id", userID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("delete user", err))
		return
	}

	// Emit lifecycle event
	s.emitUserLifecycleEvent(c.Request.Context(), "user.deleted", userID, actorID)

	c.Status(http.StatusNoContent)
}

// HandleListUsers handles GET /api/v1/users
func (s *Service) HandleListUsers(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Parse search query
	query := c.Query("q")

	// Build filter
	filter := UserFilter{
		PaginationParams: PaginationParams{
			Offset: offset,
			Limit:  limit,
		},
	}

	if query != "" {
		filter.Query = &query
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists {
		tenantIDStr, _ := tenantID.(string)
		filter.OrganizationID = &tenantIDStr
	}

	// List users
	resp, err := s.ListUsersWithFilter(c.Request.Context(), filter)
	if err != nil {
		s.logger.Error("failed to list users", zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("list users", err))
		return
	}

	users, ok := resp.Resources.([]User)
	if !ok {
		users = []User{}
	}

	c.JSON(http.StatusOK, ListUsersResponse{
		Users: users,
		Total: resp.TotalResults,
		Page:  page,
		Limit: limit,
	})
}

// HandleSearchUsers handles GET /api/v1/users/search
func (s *Service) HandleSearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		apperrors.HandleError(c, apperrors.ValidationError("search query 'q' is required"))
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	filter := UserFilter{
		PaginationParams: PaginationParams{
			Offset: offset,
			Limit:  limit,
		},
		Query: &query,
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists {
		tenantIDStr, _ := tenantID.(string)
		filter.OrganizationID = &tenantIDStr
	}

	resp, err := s.ListUsersWithFilter(c.Request.Context(), filter)
	if err != nil {
		s.logger.Error("failed to search users", zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("search users", err))
		return
	}

	users, ok := resp.Resources.([]User)
	if !ok {
		users = []User{}
	}

	c.JSON(http.StatusOK, ListUsersResponse{
		Users: users,
		Total: resp.TotalResults,
		Page:  page,
		Limit: limit,
	})
}

// ============================================================
// Group CRUD Handlers
// ============================================================

// HandleCreateGroup handles POST /api/v1/groups
func (s *Service) HandleCreateGroup(c *gin.Context) {
	var req CreateOrUpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.HandleError(c, apperrors.ValidationError("invalid request body: "+err.Error()))
		return
	}

	// Get tenant ID from context for tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	// Check for duplicate group name
	existing, _ := s.GetGroupByDisplayName(c.Request.Context(), req.DisplayName)
	if existing != nil {
		apperrors.HandleError(c, apperrors.GroupAlreadyExists(req.DisplayName))
		return
	}

	group := req.ToGroup()
	tenantIDStr, _ := tenantID.(string)
	group.OrganizationID = &tenantIDStr

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.CreateGroup(ctx, group); err != nil {
		s.logger.Error("failed to create group",
			zap.String("display_name", req.DisplayName),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("create group", err))
		return
	}

	// Emit lifecycle event
	s.emitGroupLifecycleEvent(c.Request.Context(), "group.created", group.ID, actorID)

	c.JSON(http.StatusCreated, group)
}

// HandleGetGroup handles GET /api/v1/groups/:id
func (s *Service) HandleGetGroup(c *gin.Context) {
	groupID := c.Param("id")

	// Validate tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	if group.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *group.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	c.JSON(http.StatusOK, group)
}

// HandleUpdateGroup handles PUT /api/v1/groups/:id
func (s *Service) HandleUpdateGroup(c *gin.Context) {
	groupID := c.Param("id")

	var req CreateOrUpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.HandleError(c, apperrors.ValidationError("invalid request body: "+err.Error()))
		return
	}

	// Get existing group first to enforce tenant isolation
	existing, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists && existing.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *existing.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	// Check for duplicate name if changed
	if req.DisplayName != existing.DisplayName {
		duplicate, _ := s.GetGroupByDisplayName(c.Request.Context(), req.DisplayName)
		if duplicate != nil && duplicate.ID != groupID {
			apperrors.HandleError(c, apperrors.Conflict("group name already exists"))
			return
		}
	}

	// Update group with request data
	group := req.ToGroup()
	group.ID = groupID
	group.CreatedAt = existing.CreatedAt
	if existing.OrganizationID != nil {
		group.OrganizationID = existing.OrganizationID
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.UpdateGroup(ctx, group); err != nil {
		s.logger.Error("failed to update group",
			zap.String("group_id", groupID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("update group", err))
		return
	}

	// Emit lifecycle event
	s.emitGroupLifecycleEvent(c.Request.Context(), "group.updated", group.ID, actorID)

	c.JSON(http.StatusOK, group)
}

// HandleDeleteGroup handles DELETE /api/v1/groups/:id
func (s *Service) HandleDeleteGroup(c *gin.Context) {
	groupID := c.Param("id")

	// Get existing group first to enforce tenant isolation
	existing, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists && existing.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *existing.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.DeleteGroup(ctx, groupID); err != nil {
		s.logger.Error("failed to delete group",
			zap.String("group_id", groupID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("delete group", err))
		return
	}

	// Emit lifecycle event
	s.emitGroupLifecycleEvent(c.Request.Context(), "group.deleted", groupID, actorID)

	c.Status(http.StatusNoContent)
}

// HandleListGroups handles GET /api/v1/groups
func (s *Service) HandleListGroups(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Parse search query
	query := c.Query("q")

	// Build filter
	filter := GroupFilter{
		PaginationParams: PaginationParams{
			Offset: offset,
			Limit:  limit,
		},
	}

	if query != "" {
		filter.Query = &query
	}

	// Enforce tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if exists {
		tenantIDStr, _ := tenantID.(string)
		filter.OrganizationID = &tenantIDStr
	}

	// List groups
	resp, err := s.ListGroupsWithFilter(c.Request.Context(), filter)
	if err != nil {
		s.logger.Error("failed to list groups", zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("list groups", err))
		return
	}

	groups, ok := resp.Resources.([]Group)
	if !ok {
		groups = []Group{}
	}

	c.JSON(http.StatusOK, ListGroupsResponse{
		Groups: groups,
		Total:  resp.TotalResults,
		Page:   page,
		Limit:  limit,
	})
}

// ============================================================
// Group Member Handlers
// ============================================================

// HandleGetGroupMembers handles GET /api/v1/groups/:id/members
func (s *Service) HandleGetGroupMembers(c *gin.Context) {
	groupID := c.Param("id")

	// Validate tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	if group.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *group.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	members, err := s.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		s.logger.Error("failed to get group members",
			zap.String("group_id", groupID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("get group members", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"groupId": groupID,
		"members": members,
		"total":   len(members),
	})
}

// HandleAddGroupMember handles POST /api/v1/groups/:id/members
func (s *Service) HandleAddGroupMember(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		UserID string `json:"userId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.HandleError(c, apperrors.ValidationError("invalid request body: "+err.Error()))
		return
	}

	// Validate tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	if group.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *group.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	// Verify user exists and belongs to same tenant
	user, err := s.GetUser(c.Request.Context(), req.UserID)
	if err != nil {
		apperrors.HandleError(c, apperrors.UserNotFound(req.UserID))
		return
	}

	if user.OrganizationID != nil && *user.OrganizationID != *group.OrganizationID {
		apperrors.HandleError(c, apperrors.BadRequest("user and group must belong to the same tenant"))
		return
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.AddGroupMember(ctx, groupID, req.UserID); err != nil {
		s.logger.Error("failed to add group member",
			zap.String("group_id", groupID),
			zap.String("user_id", req.UserID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("add group member", err))
		return
	}

	// Emit lifecycle event
	s.emitGroupLifecycleEvent(c.Request.Context(), "group.member_added", groupID, actorID)

	c.Status(http.StatusCreated)
}

// HandleRemoveGroupMember handles DELETE /api/v1/groups/:id/members/:userId
func (s *Service) HandleRemoveGroupMember(c *gin.Context) {
	groupID := c.Param("id")
	userID := c.Param("userId")

	// Validate tenant isolation
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		apperrors.HandleError(c, apperrors.Unauthorized("tenant context required"))
		return
	}

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		apperrors.HandleError(c, apperrors.GroupNotFound(groupID))
		return
	}

	// Enforce tenant isolation
	if group.OrganizationID != nil {
		tenantIDStr, _ := tenantID.(string)
		if *group.OrganizationID != tenantIDStr {
			apperrors.HandleError(c, apperrors.Forbidden("access to group from different tenant not allowed"))
			return
		}
	}

	actorID := getActorID(c)
	ctx := ContextWithActorID(c.Request.Context(), actorID)

	if err := s.RemoveGroupMember(ctx, groupID, userID); err != nil {
		s.logger.Error("failed to remove group member",
			zap.String("group_id", groupID),
			zap.String("user_id", userID),
			zap.Error(err))
		apperrors.HandleError(c, apperrors.DatabaseError("remove group member", err))
		return
	}

	// Emit lifecycle event
	s.emitGroupLifecycleEvent(c.Request.Context(), "group.member_removed", groupID, actorID)

	c.Status(http.StatusNoContent)
}

// ============================================================
// Helper Functions
// ============================================================

// getActorID extracts the actor ID from the Gin context
func getActorID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return "system"
}

// auditCtx is the request context a service call should run under: it carries
// the acting user and the client IP so audit_events records who did it and
// from where.
//
// Handlers that pass c.Request.Context() straight through still work, but every
// event they produce is attributed to "system" with no IP — which is to say the
// row exists and answers nothing. Prefer this at any call site that mutates
// identities, credentials, group membership, roles or federation.
func auditCtx(c *gin.Context) context.Context {
	return ContextWithActor(c.Request.Context(), getActorID(c), c.ClientIP())
}

// validateCreateUserRequest validates the user creation request
func validateCreateUserRequest(req *CreateOrUpdateUserRequest) *apperrors.AppError {
	if req.UserName == "" {
		return apperrors.ValidationError("username is required")
	}
	if len(req.UserName) < 3 {
		return apperrors.ValidationError("username must be at least 3 characters")
	}
	if req.Email == "" {
		return apperrors.ValidationError("email is required")
	}
	return nil
}

// publishCtx returns a context detached from the request lifecycle (so a client
// disconnect can't cancel the webhook write) that still carries the request's
// org. Webhook subscriptions are RLS-scoped, so without the org the publish
// would see zero subscriptions and silently emit nothing for the tenant.
func publishCtx(ctx context.Context) context.Context {
	out := context.Background()
	if org, err := orgctx.From(ctx); err == nil {
		out = orgctx.With(out, org)
	}
	return out
}

// emitUserLifecycleEvent emits a user lifecycle event. ctx must be the request
// context so the publish is scoped to the acting tenant (see publishCtx).
func (s *Service) emitUserLifecycleEvent(ctx context.Context, eventType, userID, actorID string) {
	if s.webhookService != nil {
		s.webhookService.Publish(publishCtx(ctx), eventType, map[string]interface{}{
			"user_id":  userID,
			"actor_id": actorID,
		})
	}
}

// emitGroupLifecycleEvent emits a group lifecycle event. ctx must be the request
// context so the publish is scoped to the acting tenant (see publishCtx).
func (s *Service) emitGroupLifecycleEvent(ctx context.Context, eventType, groupID, actorID string) {
	if s.webhookService != nil {
		s.webhookService.Publish(publishCtx(ctx), eventType, map[string]interface{}{
			"group_id": groupID,
			"actor_id": actorID,
		})
	}
}
