package access

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// handleGetSyncStatus returns the current user-to-Ziti sync state.
// GET /api/v1/access/ziti/sync/status
func (s *Service) handleGetSyncStatus(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	status, err := s.ziti().GetSyncStatus(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get sync status", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, status)
}

// handleSyncAllUsers triggers a full batch sync of all unsynced users.
// POST /api/v1/access/ziti/sync/users
func (s *Service) handleSyncAllUsers(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	result, err := s.ziti().SyncAllUsersToZiti(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("sync all users", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleSyncSingleUser syncs a specific user to Ziti.
// POST /api/v1/access/ziti/sync/users/:userId
func (s *Service) handleSyncSingleUser(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	userID := c.Param("userId")
	result, err := s.ziti().SyncUserToZiti(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("sync single user", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleGetUnsyncedUsers returns the list of users without Ziti identities.
// GET /api/v1/access/ziti/sync/unsynced
func (s *Service) handleGetUnsyncedUsers(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name
		FROM users u
		LEFT JOIN ziti_identities zi ON zi.user_id = u.id AND zi.org_id = u.org_id
		WHERE zi.id IS NULL AND u.enabled = true AND u.org_id = $1
		ORDER BY u.username
		LIMIT 50
	`, org.ID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get unsynced users", err), s.logger)
		return
	}
	defer rows.Close()

	type UnsyncedUser struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	var users []UnsyncedUser
	for rows.Next() {
		var u UnsyncedUser
		var firstName, lastName *string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &firstName, &lastName); err != nil {
			continue
		}
		if firstName != nil {
			u.FirstName = *firstName
		}
		if lastName != nil {
			u.LastName = *lastName
		}
		users = append(users, u)
	}
	if users == nil {
		users = []UnsyncedUser{}
	}
	c.JSON(http.StatusOK, users)
}

// handleGetMyZitiIdentity returns the current user's Ziti identity (self-service).
// GET /api/v1/access/ziti/sync/my-identity
func (s *Service) handleGetMyZitiIdentity(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		// In dev mode, try query param
		userID = c.Query("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var zitiID, name string
	var enrolled bool
	var attrs []string
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT zi.ziti_id, zi.name, zi.enrolled, zi.attributes
		FROM ziti_identities zi
		WHERE zi.user_id = $1 AND zi.org_id = $2
	`, userID, org.ID).Scan(&zitiID, &name, &enrolled, &attrs)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"linked": false})
		return
	}

	result := gin.H{
		"linked":     true,
		"ziti_id":    zitiID,
		"name":       name,
		"enrolled":   enrolled,
		"attributes": attrs,
	}

	// Self-heal the stored `enrolled` flag against the controller's live state.
	// The flag is written false at identity creation and nothing flips it true
	// when a device completes enrollment out-of-band (native SDK / tunneler), so
	// a fully-enrolled device would forever show "Pending Enrollment". If the
	// controller says the identity is enrolled, adopt that and persist it.
	if !enrolled && s.ziti() != nil {
		if live, verr := s.ziti().IsIdentityEnrolled(c.Request.Context(), zitiID); verr == nil && live {
			enrolled = true
			result["enrolled"] = true
			if _, uerr := s.db.Pool.Exec(c.Request.Context(),
				"UPDATE ziti_identities SET enrolled = TRUE, updated_at = NOW() WHERE ziti_id = $1 AND org_id = $2",
				zitiID, org.ID); uerr != nil {
				s.logger.Warn("failed to persist self-healed enrolled flag",
					zap.String("ziti_id", zitiID), zap.Error(uerr))
			}
		}
	}

	// If not enrolled, try to get enrollment JWT
	if !enrolled {
		var enrollmentJWT *string
		if err := s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT enrollment_jwt FROM ziti_identities WHERE ziti_id=$1 AND org_id=$2", zitiID, org.ID).Scan(&enrollmentJWT); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error("failed to query enrollment JWT", zap.String("ziti_id", zitiID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query enrollment JWT"})
			return
		}
		if enrollmentJWT != nil && *enrollmentJWT != "" {
			result["enrollment_jwt"] = *enrollmentJWT
		} else if s.ziti() != nil {
			jwt, jwtErr := s.ziti().GetIdentityEnrollmentJWT(c.Request.Context(), zitiID)
			if jwtErr == nil && jwt != "" {
				result["enrollment_jwt"] = jwt
			}
		}
	}

	c.JSON(http.StatusOK, result)
}

// handleGetUserZitiMap returns a mapping of user IDs to their Ziti identity info.
// GET /api/v1/access/ziti/sync/user-map
func (s *Service) handleGetUserZitiMap(c *gin.Context) {
	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT zi.user_id, zi.ziti_id, zi.name, zi.enrolled, zi.attributes
		FROM ziti_identities zi
		WHERE zi.user_id IS NOT NULL AND zi.org_id = $1
	`, org.ID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get user ziti map", err), s.logger)
		return
	}
	defer rows.Close()

	type ZitiInfo struct {
		ZitiID     string   `json:"ziti_id"`
		Name       string   `json:"name"`
		Enrolled   bool     `json:"enrolled"`
		Attributes []string `json:"attributes"`
	}
	result := make(map[string]ZitiInfo)
	for rows.Next() {
		var userID, zitiID, name string
		var enrolled bool
		var attrs []string
		if err := rows.Scan(&userID, &zitiID, &name, &enrolled, &attrs); err != nil {
			continue
		}
		if attrs == nil {
			attrs = []string{}
		}
		result[userID] = ZitiInfo{ZitiID: zitiID, Name: name, Enrolled: enrolled, Attributes: attrs}
	}
	c.JSON(http.StatusOK, result)
}

// handleSyncDeviceTrust re-syncs a user's Ziti identity attributes after
// a device trust change (trust granted or revoked).
// POST /api/v1/access/ziti/sync/device-trust/:userId
func (s *Service) handleSyncDeviceTrust(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	userID := c.Param("userId")
	if err := s.ziti().SyncDeviceTrustForUser(c.Request.Context(), userID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("sync device trust", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device trust synced", "user_id": userID})
}

// handleGetEnrichedDevices returns all devices with user info and Ziti identity status.
// GET /api/v1/access/devices/enriched
func (s *Service) handleGetEnrichedDevices(c *gin.Context) {
	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var total int
	_ = s.db.Pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM known_devices WHERE org_id = $1`, org.ID).Scan(&total)

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT d.id, d.fingerprint, COALESCE(d.name,''), COALESCE(d.ip_address,''),
		       COALESCE(d.user_agent,''), COALESCE(d.location,''), d.trusted,
		       d.last_seen_at, d.created_at,
		       u.id, u.username, COALESCE(u.email,''), COALESCE(u.first_name,''), COALESCE(u.last_name,''),
		       COALESCE(zi.ziti_id,''), COALESCE(zi.enrolled, false), COALESCE(zi.attributes, '[]')
		FROM known_devices d
		JOIN users u ON u.id = d.user_id AND u.org_id = d.org_id
		LEFT JOIN ziti_identities zi ON zi.user_id = d.user_id AND zi.org_id = d.org_id
		WHERE d.org_id = $3
		ORDER BY d.last_seen_at DESC
		LIMIT $1 OFFSET $2`, limit, offset, org.ID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get enriched devices", err), s.logger)
		return
	}
	defer rows.Close()

	type EnrichedDevice struct {
		ID           string   `json:"id"`
		Fingerprint  string   `json:"fingerprint"`
		Name         string   `json:"name"`
		IPAddress    string   `json:"ip_address"`
		UserAgent    string   `json:"user_agent"`
		Location     string   `json:"location"`
		Trusted      bool     `json:"trusted"`
		LastSeenAt   string   `json:"last_seen_at"`
		CreatedAt    string   `json:"created_at"`
		UserID       string   `json:"user_id"`
		Username     string   `json:"username"`
		Email        string   `json:"email"`
		FirstName    string   `json:"first_name"`
		LastName     string   `json:"last_name"`
		ZitiID       string   `json:"ziti_id"`
		ZitiEnrolled bool     `json:"ziti_enrolled"`
		ZitiAttrs    []string `json:"ziti_attributes"`
	}

	var devices []EnrichedDevice
	for rows.Next() {
		var d EnrichedDevice
		var lastSeen, created interface{}
		var attrs []string
		if err := rows.Scan(
			&d.ID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted,
			&lastSeen, &created,
			&d.UserID, &d.Username, &d.Email, &d.FirstName, &d.LastName,
			&d.ZitiID, &d.ZitiEnrolled, &attrs,
		); err != nil {
			continue
		}
		if lastSeen != nil {
			d.LastSeenAt = fmt.Sprintf("%v", lastSeen)
		}
		if created != nil {
			d.CreatedAt = fmt.Sprintf("%v", created)
		}
		if attrs != nil {
			d.ZitiAttrs = attrs
		} else {
			d.ZitiAttrs = []string{}
		}
		devices = append(devices, d)
	}

	if devices == nil {
		devices = []EnrichedDevice{}
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices, "total": total})
}

// handleSyncAllGroups refreshes group-based role attributes for all linked identities.
// POST /api/v1/access/ziti/sync/groups
func (s *Service) handleSyncAllGroups(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	result, err := s.ziti().SyncAllGroupAttributes(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("sync all groups", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, result)
}
