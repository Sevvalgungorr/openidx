package handlers

import (
	"context"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/selfheal"
	"go.uber.org/zap"
)

// AuditFunc records a self-heal control action. The caller adapts it to the
// admin audit log (actor from the gin context, before→after states). Kept as a
// callback so this handler stays free of the admin.Service/DB dependency.
type AuditFunc func(c *gin.Context, action string, before, after interface{})

// SelfHealHandler exposes the self-heal loop's on-disk state (findings, history,
// health) and its controls (mode, kill-switch, on-demand sweep) to the admin
// console. Reads are RequireAdmin; mutations additionally require
// selfheal:manage and are audited.
type SelfHealHandler struct {
	logger     *zap.Logger
	store      *selfheal.Store
	scriptsDir string
	audit      AuditFunc
}

// NewSelfHealHandler builds the handler over the given state + scripts dirs.
// auditFn may be nil (a no-op is used) to keep tests simple.
func NewSelfHealHandler(logger *zap.Logger, stateDir, scriptsDir string, auditFn AuditFunc) *SelfHealHandler {
	if auditFn == nil {
		auditFn = func(*gin.Context, string, interface{}, interface{}) {}
	}
	return &SelfHealHandler{
		logger:     logger.With(zap.String("handler", "selfheal")),
		store:      selfheal.New(stateDir),
		scriptsDir: scriptsDir,
		audit:      auditFn,
	}
}

// GetStatus returns current mode + kill-switch + the latest snapshot summary.
func (h *SelfHealHandler) GetStatus(c *gin.Context) {
	mode, err := h.store.Mode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read mode: " + err.Error()})
		return
	}
	kill, err := h.store.KillSwitch()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read kill-switch: " + err.Error()})
		return
	}
	snap, stale, err := h.store.Status()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read snapshot: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"mode":        mode,
		"kill_switch": kill,
		"stale":       stale,
		"snapshot_ts": snap.TS,
		"findings":    snap.Findings,
	})
}

// GetFindings returns the deduped ledger, filterable by class/severity/status.
func (h *SelfHealHandler) GetFindings(c *gin.Context) {
	f, err := h.store.Findings(selfheal.FindingFilter{
		Class:    c.Query("class"),
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"findings": f})
}

// GetHistory returns recent remediation outcomes (default 50).
func (h *SelfHealHandler) GetHistory(c *gin.Context) {
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	hist, err := h.store.History(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"actions": hist})
}

type putModeReq struct {
	Mode    string `json:"mode"`
	Confirm string `json:"confirm"`
}

// PutMode sets the autonomy mode. tier1 (autonomous code-fix) is the most
// dangerous setting, so it requires an explicit confirm token equal to "tier1"
// — the server double-checks the typed confirmation the UI enforces.
func (h *SelfHealHandler) PutMode(c *gin.Context) {
	var req putModeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if !selfheal.ValidMode(req.Mode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mode: " + req.Mode})
		return
	}
	if req.Mode == "tier1" && req.Confirm != "tier1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tier1 requires confirm=\"tier1\""})
		return
	}
	before, _ := h.store.Mode()
	if err := h.store.SetMode(req.Mode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "selfheal.mode.set", gin.H{"mode": before}, gin.H{"mode": req.Mode})
	c.JSON(http.StatusOK, gin.H{"mode": req.Mode})
}

type killSwitchReq struct {
	Enabled bool `json:"enabled"`
}

// PostKillSwitch toggles the DISABLE file — enabling it halts ALL autonomy.
func (h *SelfHealHandler) PostKillSwitch(c *gin.Context) {
	var req killSwitchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	before, _ := h.store.KillSwitch()
	if err := h.store.SetKillSwitch(req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "selfheal.kill_switch.set", gin.H{"enabled": before}, gin.H{"enabled": req.Enabled})
	c.JSON(http.StatusOK, gin.H{"kill_switch": req.Enabled})
}

// PostSweep runs one self-heal cycle on demand (the only shell-out). Bounded by
// a hard timeout so a wedged collector can't hang the request.
func (h *SelfHealHandler) PostSweep(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	script := filepath.Join(h.scriptsDir, "selfheal-watch.sh")
	out, err := exec.CommandContext(ctx, "bash", script).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "sweep timed out"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "output": string(out)})
		return
	}
	h.audit(c, "selfheal.sweep", nil, gin.H{"ran": true})
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}

// SelfHealRoutes registers the panel routes. Reads are guarded by adminMW;
// mutations by adminMW + manageMW (selfheal:manage).
func SelfHealRoutes(router *gin.RouterGroup, handler *SelfHealHandler, adminMW, manageMW gin.HandlerFunc) {
	read := router.Group("/selfheal")
	if adminMW != nil {
		read.Use(adminMW)
	}
	{
		read.GET("/status", handler.GetStatus)
		read.GET("/findings", handler.GetFindings)
		read.GET("/history", handler.GetHistory)
	}

	mutate := router.Group("/selfheal")
	if adminMW != nil {
		mutate.Use(adminMW)
	}
	if manageMW != nil {
		mutate.Use(manageMW)
	}
	{
		mutate.PUT("/mode", handler.PutMode)
		mutate.POST("/kill-switch", handler.PostKillSwitch)
		mutate.POST("/sweep", handler.PostSweep)
	}
}
