// Package access - OpenZiti fabric management, health monitoring, and metrics
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ZitiEdgeRouterInfo represents a Ziti edge router from the management API
type ZitiEdgeRouterInfo struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Hostname       string                 `json:"hostname"`
	IsOnline       bool                   `json:"isOnline"`
	IsVerified     bool                   `json:"isVerified"`
	RoleAttributes []string               `json:"roleAttributes"`
	VersionInfo    *ZitiEdgeRouterVersion `json:"versionInfo,omitempty"`
	// Computed fields for DB sync / display
	Os      string `json:"-"`
	Arch    string `json:"-"`
	Version string `json:"-"`
}

// ZitiEdgeRouterVersion represents the nested versionInfo object from the Ziti API
type ZitiEdgeRouterVersion struct {
	Os      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
}

// ZitiServicePolicyInfo represents a Ziti service policy from the management API
type ZitiServicePolicyInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	ServiceRoles  []string `json:"serviceRoles"`
	IdentityRoles []string `json:"identityRoles"`
}

// FabricHealthStatus represents the health of the Ziti fabric
type FabricHealthStatus struct {
	ControllerReachable bool                   `json:"controller_reachable"`
	ControllerVersion   string                 `json:"controller_version"`
	SDKReady            bool                   `json:"sdk_ready"`
	RoutersOnline       int                    `json:"routers_online"`
	RoutersTotal        int                    `json:"routers_total"`
	ServicesCount       int                    `json:"services_count"`
	IdentitiesCount     int                    `json:"identities_count"`
	PoliciesCount       int                    `json:"policies_count"`
	LastChecked         time.Time              `json:"last_checked"`
	Details             map[string]interface{} `json:"details,omitempty"`
}

// FabricOverview provides a high-level summary of the Ziti fabric state
type FabricOverview struct {
	Health        FabricHealthStatus   `json:"health"`
	RecentMetrics []ZitiMetric         `json:"recent_metrics"`
	Routers       []ZitiEdgeRouterInfo `json:"routers"`
}

// ZitiMetric represents a recorded fabric metric
type ZitiMetric struct {
	ID         string            `json:"id"`
	MetricType string            `json:"metric_type"`
	Source     string            `json:"source"`
	Value      float64           `json:"value"`
	Labels     map[string]string `json:"labels"`
	RecordedAt time.Time         `json:"recorded_at"`
}

// ---- Edge Router Management ----

// ListEdgeRouters retrieves all edge routers from the Ziti controller and syncs them to the database
func (zm *ZitiManager) ListEdgeRouters(ctx context.Context) ([]ZitiEdgeRouterInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/edge-routers?limit=1000", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list edge routers: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing edge routers", statusCode)
	}

	var resp struct {
		Data []ZitiEdgeRouterInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse edge routers response: %w", err)
	}

	// Populate computed fields from nested versionInfo
	for i := range resp.Data {
		if resp.Data[i].VersionInfo != nil {
			resp.Data[i].Os = resp.Data[i].VersionInfo.Os
			resp.Data[i].Arch = resp.Data[i].VersionInfo.Arch
			resp.Data[i].Version = resp.Data[i].VersionInfo.Version
		}
	}

	// Sync routers to database
	for _, router := range resp.Data {
		roleAttrsJSON, _ := json.Marshal(router.RoleAttributes)
		_, dbErr := zm.db.Pool.Exec(ctx,
			`INSERT INTO ziti_edge_routers (ziti_id, name, hostname, is_online, is_verified, role_attributes, os, arch, version, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
			 ON CONFLICT (ziti_id) DO UPDATE SET
			   name=$2, hostname=$3, is_online=$4, is_verified=$5, role_attributes=$6,
			   os=$7, arch=$8, version=$9, updated_at=NOW()`,
			router.ID, router.Name, router.Hostname, router.IsOnline, router.IsVerified,
			string(roleAttrsJSON), router.Os, router.Arch, router.Version)
		if dbErr != nil {
			zm.logger.Warn("Failed to sync edge router to DB",
				zap.String("router_id", router.ID), zap.Error(dbErr))
		}
	}

	zm.logger.Debug("Listed edge routers", zap.Int("count", len(resp.Data)))
	return resp.Data, nil
}

// GetEdgeRouter retrieves a single edge router by ID from the Ziti controller
func (zm *ZitiManager) GetEdgeRouter(ctx context.Context, routerID string) (*ZitiEdgeRouterInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/edge-routers/%s", routerID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge router %s: %w", routerID, err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d getting edge router %s", statusCode, routerID)
	}

	var resp struct {
		Data ZitiEdgeRouterInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse edge router response: %w", err)
	}

	if resp.Data.VersionInfo != nil {
		resp.Data.Os = resp.Data.VersionInfo.Os
		resp.Data.Arch = resp.Data.VersionInfo.Arch
		resp.Data.Version = resp.Data.VersionInfo.Version
	}

	return &resp.Data, nil
}

// ---- Policy Listing ----

// ListServicePolicies retrieves all service policies from the Ziti controller
func (zm *ZitiManager) ListServicePolicies(ctx context.Context) ([]ZitiServicePolicyInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/service-policies?limit=1000", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list service policies: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing service policies", statusCode)
	}

	var resp struct {
		Data []ZitiServicePolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse service policies response: %w", err)
	}

	zm.logger.Debug("Listed service policies", zap.Int("count", len(resp.Data)))
	return resp.Data, nil
}

// ListEdgeRouterPolicies retrieves all edge router policies from the Ziti controller
func (zm *ZitiManager) ListEdgeRouterPolicies(ctx context.Context) ([]ZitiServicePolicyInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/edge-router-policies?limit=1000", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list edge router policies: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing edge router policies", statusCode)
	}

	var resp struct {
		Data []ZitiServicePolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse edge router policies response: %w", err)
	}

	zm.logger.Debug("Listed edge router policies", zap.Int("count", len(resp.Data)))
	return resp.Data, nil
}

// ---- Health Monitoring ----

// HealthCheck performs a comprehensive health check of the Ziti fabric
func (zm *ZitiManager) HealthCheck(ctx context.Context) (*FabricHealthStatus, error) {
	status := &FabricHealthStatus{
		LastChecked: time.Now(),
		Details:     make(map[string]interface{}),
	}

	// Check controller connectivity
	versionData, err := zm.GetControllerVersion(ctx)
	if err != nil {
		status.ControllerReachable = false
		status.Details["controller_error"] = err.Error()
	} else {
		status.ControllerReachable = true
		if data, ok := versionData["data"].(map[string]interface{}); ok {
			if version, ok := data["version"].(string); ok {
				status.ControllerVersion = version
			}
		}
	}

	// Check SDK context readiness
	zm.mu.RLock()
	status.SDKReady = zm.initialized && zm.zitiCtx != nil
	zm.mu.RUnlock()

	// Check router status
	if status.ControllerReachable {
		routers, err := zm.ListEdgeRouters(ctx)
		if err != nil {
			status.Details["routers_error"] = err.Error()
		} else {
			status.RoutersTotal = len(routers)
			for _, r := range routers {
				if r.IsOnline {
					status.RoutersOnline++
				}
			}
		}

		// Count services
		services, err := zm.ListServices(ctx)
		if err != nil {
			status.Details["services_error"] = err.Error()
		} else {
			status.ServicesCount = len(services)
		}

		// Count identities
		identities, err := zm.ListIdentities(ctx)
		if err != nil {
			status.Details["identities_error"] = err.Error()
		} else {
			status.IdentitiesCount = len(identities)
		}

		// Count policies
		policies, err := zm.ListServicePolicies(ctx)
		if err != nil {
			status.Details["policies_error"] = err.Error()
		} else {
			status.PoliciesCount = len(policies)
		}
	}

	return status, nil
}

// StartHealthMonitor launches a background goroutine that periodically checks fabric health,
// re-authenticates if the controller becomes unreachable, and records metrics
func (zm *ZitiManager) StartHealthMonitor(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		zm.logger.Info("Ziti health monitor started", zap.Duration("interval", 30*time.Second))

		for {
			select {
			case <-ctx.Done():
				zm.logger.Info("Ziti health monitor stopped")
				return
			case <-ticker.C:
				zm.runHealthCycle(ctx)
			}
		}
	}()
}

func (zm *ZitiManager) runHealthCycle(ctx context.Context) {
	status, err := zm.HealthCheck(ctx)
	if err != nil {
		zm.logger.Error("Health check failed", zap.Error(err))
		return
	}

	zm.logger.Debug("Health check completed",
		zap.Bool("controller_reachable", status.ControllerReachable),
		zap.Bool("sdk_ready", status.SDKReady),
		zap.Int("routers_online", status.RoutersOnline),
		zap.Int("routers_total", status.RoutersTotal))

	// If controller is unreachable, attempt reconnect
	if !status.ControllerReachable {
		zm.logger.Warn("Ziti controller unreachable, attempting re-authentication...")
		if err := zm.authenticate(); err != nil {
			zm.logger.Error("Re-authentication failed", zap.Error(err))
			_ = zm.RecordMetric(ctx, "health.controller_reachable", "health_monitor", 0, nil)
		} else {
			zm.logger.Info("Re-authentication successful")
			_ = zm.RecordMetric(ctx, "health.controller_reachable", "health_monitor", 1, map[string]string{"event": "reconnected"})
		}
	} else {
		_ = zm.RecordMetric(ctx, "health.controller_reachable", "health_monitor", 1, nil)
	}

	// Record fabric metrics
	_ = zm.RecordMetric(ctx, "health.routers_online", "health_monitor", float64(status.RoutersOnline), nil)
	_ = zm.RecordMetric(ctx, "health.routers_total", "health_monitor", float64(status.RoutersTotal), nil)
	_ = zm.RecordMetric(ctx, "health.services_count", "health_monitor", float64(status.ServicesCount), nil)
	_ = zm.RecordMetric(ctx, "health.identities_count", "health_monitor", float64(status.IdentitiesCount), nil)
	_ = zm.RecordMetric(ctx, "health.policies_count", "health_monitor", float64(status.PoliciesCount), nil)

	sdkReadyVal := 0.0
	if status.SDKReady {
		sdkReadyVal = 1.0
	}
	_ = zm.RecordMetric(ctx, "health.sdk_ready", "health_monitor", sdkReadyVal, nil)
}

// ---- Metrics ----

// RecordMetric inserts a metric record into the ziti_metrics table
func (zm *ZitiManager) RecordMetric(ctx context.Context, metricType, source string, value float64, labels map[string]string) error {
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		labelsJSON = []byte("{}")
	}

	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO ziti_metrics (metric_type, source, value, labels, recorded_at)
		 VALUES ($1, $2, $3, $4, NOW())`,
		metricType, source, value, string(labelsJSON))
	if err != nil {
		zm.logger.Warn("Failed to record metric",
			zap.String("metric_type", metricType),
			zap.String("source", source),
			zap.Error(err))
		return fmt.Errorf("failed to record metric: %w", err)
	}

	return nil
}

// GetMetrics retrieves metrics from the ziti_metrics table filtered by type and time range
func (zm *ZitiManager) GetMetrics(ctx context.Context, metricType string, since time.Time, limit int) ([]ZitiMetric, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := zm.db.Pool.Query(ctx,
		`SELECT id, metric_type, source, value, labels, recorded_at
		 FROM ziti_metrics
		 WHERE metric_type = $1 AND recorded_at >= $2
		 ORDER BY recorded_at DESC
		 LIMIT $3`,
		metricType, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics: %w", err)
	}
	defer rows.Close()

	var metrics []ZitiMetric
	for rows.Next() {
		var m ZitiMetric
		var labelsStr string
		if err := rows.Scan(&m.ID, &m.MetricType, &m.Source, &m.Value, &labelsStr, &m.RecordedAt); err != nil {
			zm.logger.Warn("Failed to scan metric row", zap.Error(err))
			continue
		}
		if labelsStr != "" {
			_ = json.Unmarshal([]byte(labelsStr), &m.Labels)
		}
		if m.Labels == nil {
			m.Labels = make(map[string]string)
		}
		metrics = append(metrics, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating metric rows: %w", err)
	}

	return metrics, nil
}

// ---- Reconnect ----

// Reconnect performs a full reconnection to the Ziti controller, re-authenticating and
// re-initializing the SDK context if needed
func (zm *ZitiManager) Reconnect(ctx context.Context) error {
	zm.logger.Info("Initiating full Ziti reconnect...")

	// Re-authenticate to the management API
	if err := zm.authenticate(); err != nil {
		return fmt.Errorf("reconnect: failed to re-authenticate: %w", err)
	}
	zm.logger.Info("Reconnect: re-authenticated to management API")

	// Re-initialize SDK context if identity file exists
	identityFile := filepath.Join(zm.cfg.ZitiIdentityDir, "access-proxy.json")
	if _, err := os.Stat(identityFile); err == nil {
		// Close existing context if present
		zm.mu.Lock()
		if zm.zitiCtx != nil {
			zm.zitiCtx.Close()
			zm.zitiCtx = nil
			zm.initialized = false
		}
		zm.mu.Unlock()

		zitiCfg, err := ziti.NewConfigFromFile(identityFile)
		if err != nil {
			return fmt.Errorf("reconnect: failed to load ziti identity from %s: %w", identityFile, err)
		}

		zitiCtx, err := ziti.NewContext(zitiCfg)
		if err != nil {
			return fmt.Errorf("reconnect: failed to create ziti context: %w", err)
		}

		zm.mu.Lock()
		zm.zitiCtx = zitiCtx
		zm.initialized = true
		zm.mu.Unlock()

		zm.logger.Info("Reconnect: SDK context re-initialized", zap.String("file", identityFile))
	} else {
		zm.logger.Warn("Reconnect: identity file not found, SDK context not re-initialized",
			zap.String("file", identityFile))
	}

	// Verify connectivity by fetching controller version
	if _, err := zm.GetControllerVersion(ctx); err != nil {
		return fmt.Errorf("reconnect: controller connectivity verification failed: %w", err)
	}

	zm.logger.Info("Ziti reconnect completed successfully")
	return nil
}

// ---- Fabric Overview ----

// GetFabricOverview returns a comprehensive overview of the Ziti fabric including
// health status, router information, and recent metrics
func (zm *ZitiManager) GetFabricOverview(ctx context.Context) (*FabricOverview, error) {
	overview := &FabricOverview{}

	// Get health status
	health, err := zm.HealthCheck(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}
	overview.Health = *health

	// Get routers
	routers, err := zm.ListEdgeRouters(ctx)
	if err != nil {
		zm.logger.Warn("Failed to list routers for fabric overview", zap.Error(err))
		overview.Routers = []ZitiEdgeRouterInfo{}
	} else {
		overview.Routers = routers
	}

	// Get recent metrics (last hour)
	since := time.Now().Add(-1 * time.Hour)
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT id, metric_type, source, value, labels, recorded_at
		 FROM ziti_metrics
		 WHERE recorded_at >= $1
		 ORDER BY recorded_at DESC
		 LIMIT 50`,
		since)
	if err != nil {
		zm.logger.Warn("Failed to query recent metrics for fabric overview", zap.Error(err))
		overview.RecentMetrics = []ZitiMetric{}
	} else {
		defer rows.Close()
		var metrics []ZitiMetric
		for rows.Next() {
			var m ZitiMetric
			var labelsStr string
			if err := rows.Scan(&m.ID, &m.MetricType, &m.Source, &m.Value, &labelsStr, &m.RecordedAt); err != nil {
				continue
			}
			if labelsStr != "" {
				_ = json.Unmarshal([]byte(labelsStr), &m.Labels)
			}
			if m.Labels == nil {
				m.Labels = make(map[string]string)
			}
			metrics = append(metrics, m)
		}
		if metrics == nil {
			metrics = []ZitiMetric{}
		}
		overview.RecentMetrics = metrics
	}

	return overview, nil
}
