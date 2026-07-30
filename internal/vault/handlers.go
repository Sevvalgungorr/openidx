package vault

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// RegisterRoutes mounts the vault API under an already-admin-guarded group.
// The caller passes a group that has tenant-resolution + auth applied
// (same middleware the other admin-api resources use).
func (s *Service) RegisterRoutes(g *gin.RouterGroup) {
	v := g.Group("/vault/secrets")
	v.POST("", s.handleCreate)
	v.GET("", s.handleList)
	v.GET("/:id", s.handleGet)
	v.PUT("/:id/version", s.handleNewVersion)
	v.DELETE("/:id", s.handleDelete)
	v.POST("/:id/reveal", s.handleReveal)
	v.POST("/:id/grants", s.handleAddGrant)
	v.GET("/:id/grants", s.handleListGrants)
	v.DELETE("/:id/grants/:grantId", s.handleRemoveGrant)
	v.GET("/:id/checkouts", s.handleCheckouts)
}

type createReq struct {
	Name          string                 `json:"name" binding:"required"`
	Type          string                 `json:"type"`
	Description   string                 `json:"description"`
	Value         string                 `json:"value" binding:"required"`
	Metadata      map[string]interface{} `json:"metadata"`
	OwnerID       string                 `json:"owner_id"`
	RequireStepUp bool                   `json:"require_step_up"`
}

func (s *Service) handleCreate(c *gin.Context) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	meta, err := s.Store(c.Request.Context(), StoreInput{
		Name: req.Name, Type: req.Type, Description: req.Description,
		Value: []byte(req.Value), Metadata: req.Metadata,
		OwnerID: req.OwnerID, CreatedBy: currentUserID(c),
		RequireStepUp: req.RequireStepUp,
	})
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create", err), s.logger)
		return
	}
	c.JSON(http.StatusCreated, meta) // meta carries no value
}

func (s *Service) handleList(c *gin.Context) {
	out, err := s.List(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secrets": out})
}

func (s *Service) handleGet(c *gin.Context) {
	d, err := s.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, d)
}

func (s *Service) handleNewVersion(c *gin.Context) {
	var req struct {
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := s.NewVersion(c.Request.Context(), c.Param("id"), []byte(req.Value), currentUserID(c))
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("new version", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": v})
}

func (s *Service) handleDelete(c *gin.Context) {
	if err := s.Delete(c.Request.Context(), c.Param("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete", err), s.logger)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleReveal(c *gin.Context) {
	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return
	}
	pt, err := s.Reveal(c.Request.Context(), c.Param("id"), currentUserID(c), currentUserRoles(c), req.Reason, isAdmin(c))
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
		if errors.Is(err, ErrStepUpRequired) {
			// Tell the client to run the step-up flow and retry. The header lets
			// the console distinguish this from an ordinary 403.
			c.Header("X-Step-Up-Required", "true")
			c.JSON(http.StatusForbidden, gin.H{
				"error":            "step-up authentication required",
				"step_up_required": true,
			})
			return
		}
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("reveal", err), s.logger)
		return
	}
	// Returned once. Do not log the body.
	// NOTE: zero(pt) clears the source []byte but not the string copy that
	// c.JSON/the JSON encoder holds in the response buffer. That copy is
	// GC-managed and cannot be zeroed without a manual encoder rewrite.
	c.JSON(http.StatusOK, gin.H{"value": string(pt)})
	zero(pt)
}

func (s *Service) handleAddGrant(c *gin.Context) {
	var g Grant
	if err := c.ShouldBindJSON(&g); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	g.SecretID = c.Param("id")
	g.GrantedBy = currentUserID(c)
	id, err := s.AddGrant(c.Request.Context(), g)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("add grant", err), s.logger)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) handleListGrants(c *gin.Context) {
	grants, err := s.ListGrants(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list grants", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"grants": grants})
}

func (s *Service) handleRemoveGrant(c *gin.Context) {
	if err := s.RemoveGrant(c.Request.Context(), c.Param("grantId")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleCheckouts(c *gin.Context) {
	out, err := s.Checkouts(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("checkouts", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"checkouts": out})
}

// ---- auth context helpers ----
//
// The Auth middleware (internal/common/middleware/middleware.go) sets:
//
//	"user_id" → string   (JWT sub claim; middleware.go:429-431)
//	"roles"   → []string (JWT roles claim; middleware.go:445-451)
//
// There is no "is_admin" key on the context. Admin status is derived from
// the role hierarchy defined in internal/auth/roles.go: both "admin" and
// "super_admin" are considered admin-level (IsHigherOrEqual(RoleAdmin)).
// The same check is used by auth.HasRoleInContext and the admin-api's
// RequireRole guard. Assumption: vault treat both "admin" and "super_admin"
// as bypassing the grant requirement on Reveal — consistent with the rest
// of the admin API's access model.

// currentUserID returns the authenticated user's ID from the gin context.
// Key "user_id" is set as a string by Auth middleware (middleware.go:429-431).
func currentUserID(c *gin.Context) string {
	id, _ := c.Get("user_id")
	s, _ := id.(string)
	return s
}

// currentUserRoles returns the authenticated user's roles from the gin context.
// Key "roles" is set as []string by Auth middleware (middleware.go:445-451).
func currentUserRoles(c *gin.Context) []string {
	raw, _ := c.Get("roles")
	roles, _ := raw.([]string)
	return roles
}

// isAdmin reports whether the caller holds an admin-level role.
// Derived from currentUserRoles: "admin" or "super_admin" qualify
// (mirrors auth.RoleAdmin.IsHigherOrEqual and auth.HasRoleInContext from
// internal/auth/context.go:182-183 and internal/auth/roles.go:92-93).
func isAdmin(c *gin.Context) bool {
	for _, r := range currentUserRoles(c) {
		if r == "admin" || r == "super_admin" {
			return true
		}
	}
	return false
}
