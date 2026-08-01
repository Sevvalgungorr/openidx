package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// SSF HTTP surface: stream management (RFC 8935-style), the SSF configuration
// metadata document, and the receiver push endpoint. Registered in
// RegisterRoutes.

// ssfRequireOrg resolves the caller's tenant for a stream-management request
// and FAILS CLOSED: when no org can be resolved it aborts with 403 instead of
// returning "".
//
// This used to return an empty string on failure, which was then fed into
// ssf.go's org predicates. Those carried an OR-escape that treated an empty
// org as "match every row", so an unscoped caller could read, create and
// delete every tenant's streams. Both halves are fixed: the predicates are now
// strict equality, and this helper never yields an empty org.
func (s *Service) ssfRequireOrg(c *gin.Context) (string, bool) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil || org.ID == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return "", false
	}
	return org.ID, true
}

// handleSSFConfiguration serves /.well-known/ssf-configuration (the transmitter
// metadata a receiver reads to discover the stream + status endpoints).
func (s *Service) handleSSFConfiguration(c *gin.Context) {
	base := s.issuer
	if org, err := orgctx.From(c.Request.Context()); err == nil {
		base = s.issuerForOrg(org)
	}
	c.JSON(http.StatusOK, gin.H{
		"spec_version":            "1_0",
		"issuer":                  base,
		"jwks_uri":                base + "/.well-known/jwks.json",
		"configuration_endpoint":  base + "/ssf/streams",
		"status_endpoint":         base + "/ssf/status",
		"add_subject_endpoint":    base + "/ssf/subjects:add",
		"remove_subject_endpoint": base + "/ssf/subjects:remove",
		"delivery_methods_supported": []string{
			"https://schemas.openid.net/secevent/risc/delivery-method/push",
		},
		"events_supported": []string{
			EventSessionRevoked, EventCredentialChange, EventAssuranceLevelChange,
			EventTokenClaimsChange, EventDeviceComplianceChange,
			EventAccountDisabled, EventAccountPurged,
		},
	})
}

func (s *Service) handleListSSFStreams(c *gin.Context) {
	orgID, ok := s.ssfRequireOrg(c)
	if !ok {
		return
	}
	streams, err := s.ListSSFStreams(c.Request.Context(), orgID)
	if err != nil {
		s.logger.Error("list ssf streams failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if streams == nil {
		streams = []SSFStream{}
	}
	c.JSON(http.StatusOK, streams)
}

func (s *Service) handleCreateSSFStream(c *gin.Context) {
	orgID, ok := s.ssfRequireOrg(c)
	if !ok {
		return
	}
	var in SSFStreamInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	stream, err := s.CreateSSFStream(c.Request.Context(), orgID, &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Info("SSF stream created", zap.String("id", stream.ID), zap.String("aud", stream.Audience))
	c.JSON(http.StatusCreated, stream)
}

func (s *Service) handleGetSSFStream(c *gin.Context) {
	orgID, ok := s.ssfRequireOrg(c)
	if !ok {
		return
	}
	stream, err := s.GetSSFStream(c.Request.Context(), orgID, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "stream not found"})
		return
	}
	c.JSON(http.StatusOK, stream)
}

func (s *Service) handleDeleteSSFStream(c *gin.Context) {
	orgID, ok := s.ssfRequireOrg(c)
	if !ok {
		return
	}
	if err := s.DeleteSSFStream(c.Request.Context(), orgID, c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// handleSSFVerify implements the SSF verification event: emit a test SET to the
// stream so the receiver can confirm end-to-end delivery.
func (s *Service) handleSSFVerify(c *gin.Context) {
	orgID, ok := s.ssfRequireOrg(c)
	if !ok {
		return
	}
	id := c.Param("id")
	stream, err := s.GetSSFStream(c.Request.Context(), orgID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "stream not found"})
		return
	}
	setJWT, _, err := s.BuildSET(stream.Audience,
		"https://schemas.openid.net/secevent/ssf/event-type/verification", "", "verification",
		map[string]interface{}{"state": c.Query("state")})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not build verification SET"})
		return
	}
	_, err = s.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO ssf_stream_delivery (org_id, stream_id, event_type, subject, set_jwt)
        VALUES ($1,$2,$3,$4,$5)`,
		orgID, id,
		"https://schemas.openid.net/secevent/ssf/event-type/verification", "verification", setJWT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enqueue verification"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "verification enqueued"})
}
