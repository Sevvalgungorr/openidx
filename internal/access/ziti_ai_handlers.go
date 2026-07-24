package access

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// ---------------------------------------------------------------------------
// Ziti AI network intelligence handlers
// ---------------------------------------------------------------------------

// handleZitiAIInsights returns the aggregated intelligence overview: risk
// distribution, anomaly counts, recommendation count and the controller's
// v2.0-generation feature set.
func (s *Service) handleZitiAIInsights(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	ctx := c.Request.Context()
	zm := s.ziti()

	risks, err := zm.ComputeZitiIdentityRisks(ctx)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("compute identity risks", err), s.logger)
		return
	}
	levels := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	atRisk := 0
	for _, r := range risks {
		levels[r.Level]++
		if r.Level == "high" || r.Level == "critical" {
			atRisk++
		}
	}
	topRisks := risks
	if len(topRisks) > 10 {
		topRisks = topRisks[:10]
	}

	openAnomalies, err := zm.ListZitiAnomalies(ctx, "open", 500)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list anomalies", err), s.logger)
		return
	}

	// Recommendations and controller features are best-effort enrichment: a
	// degraded controller should not blank the whole insights panel.
	recommendations, err := zm.GenerateZitiRecommendations(ctx)
	if err != nil {
		s.logger.Debug("ziti ai insights: recommendations unavailable")
		recommendations = []ZitiRecommendation{}
	}
	var features *ZitiControllerFeatures
	if f, err := zm.GetControllerFeatures(ctx); err == nil {
		features = f
	}

	c.JSON(http.StatusOK, gin.H{
		"identities_total":     len(risks),
		"identities_at_risk":   atRisk,
		"risk_levels":          levels,
		"top_risks":            topRisks,
		"open_anomalies":       len(openAnomalies),
		"recommendation_count": len(recommendations),
		"controller_features":  features,
	})
}

// handleZitiAIAnalyze runs one analysis pass now (snapshot → detect → learn).
func (s *Service) handleZitiAIAnalyze(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	result, err := s.ziti().RunZitiAIAnalysis(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("run ziti ai analysis", err), s.logger)
		return
	}
	s.logAuditEvent(c, "ziti_ai_analysis_run", "", "ziti_ai", map[string]interface{}{
		"observations":  result.Observations,
		"new_anomalies": result.NewAnomalies,
	})
	c.JSON(http.StatusOK, result)
}

func (s *Service) handleListZitiAnomalies(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	anomalies, err := s.ziti().ListZitiAnomalies(c.Request.Context(), c.Query("status"), limit)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list ziti anomalies", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, anomalies)
}

func (s *Service) handleUpdateZitiAnomalyStatus(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := c.Param("id")
	if err := s.ziti().UpdateZitiAnomalyStatus(c.Request.Context(), id, req.Status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logAuditEvent(c, "ziti_ai_anomaly_status_changed", id, "ziti_anomaly", map[string]interface{}{
		"status": req.Status,
	})
	c.JSON(http.StatusOK, gin.H{"message": "anomaly updated", "status": req.Status})
}

func (s *Service) handleZitiIdentityRisk(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	risks, err := s.ziti().ComputeZitiIdentityRisks(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("compute identity risks", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, risks)
}

func (s *Service) handleZitiAIRecommendations(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	recommendations, err := s.ziti().GenerateZitiRecommendations(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("generate ziti recommendations", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, recommendations)
}

func (s *Service) handleQuarantineZitiIdentity(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req) // reason is optional; body may be empty

	id := c.Param("id")
	terminated, err := s.ziti().QuarantineZitiIdentity(c.Request.Context(), id, req.Reason, c.GetString("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logAuditEvent(c, "ziti_identity_quarantined", id, "ziti_identity", map[string]interface{}{
		"identity_id":         id,
		"reason":              req.Reason,
		"sessions_terminated": terminated,
	})
	c.JSON(http.StatusOK, gin.H{
		"message":             "identity quarantined",
		"sessions_terminated": terminated,
	})
}

func (s *Service) handleUnquarantineZitiIdentity(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	if err := s.ziti().UnquarantineZitiIdentity(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logAuditEvent(c, "ziti_identity_unquarantined", id, "ziti_identity", map[string]interface{}{
		"identity_id": id,
	})
	c.JSON(http.StatusOK, gin.H{"message": "identity restored"})
}

// handleZitiControllerFeatures reports the controller's version and its
// v2.0-generation capability flags (HA, OIDC/JWT auth, granular permissions).
func (s *Service) handleZitiControllerFeatures(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	features, err := s.ziti().GetControllerFeatures(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get controller features", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, features)
}
