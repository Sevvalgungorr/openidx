// Package access — PAM OpenZiti reach mode (zero-trust target hop).
//
// A brokered PAM session normally has guacd dial the target host:port directly.
// "Ziti reach mode" moves that hop onto the OpenZiti overlay: access-service
// provisions a per-entry Ziti service whose host.v1 config is hosted by the
// edge routers straight to the target, and the PAM broker's ziti-tunnel binds a
// stable loopback port for it. At connect time the Guacamole connection points
// at 127.0.0.1:<loopback> instead of the real target, so guacd reaches the
// target over the mutually-authenticated, end-to-end-encrypted overlay and the
// target exposes NO inbound RDP/SSH/VNC port to the broker network.
//
// Enable/disable is a per-entry toggle (admin): enable provisions the service +
// Bind(→#ziti-routers)/Dial(→#pam-broker-dialers) policies and allocates the
// loopback port; disable tears the service down and reverts the entry to direct.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	// pamZitiServicePrefix names the per-entry Ziti service. The suffix is the
	// entry id, giving a globally-unique service name. The bind/dial/serp policy
	// and host.v1 config names derive from it so TeardownZitiServiceByName
	// (which keys off openidx-bind-/openidx-dial-/openidx-serp-/<svc>-host)
	// cleans everything up.
	pamZitiServicePrefix = "openidx-pam-"

	// pamBrokerDialerRole is the identity role attribute the PAM broker's
	// ziti-tunnel enrolls under. Only it may DIAL a PAM entry's service.
	pamBrokerDialerRole = "#pam-broker-dialers"

	// pamZitiRouterRole is the role every edge router carries (see
	// EnsureRouterRoleAttribute). Edge-router-hosted mode grants BIND to it, so
	// the router terminates the service straight to the target — no software on
	// the target network beyond a router.
	pamZitiRouterRole = "#ziti-routers"

	// pamZitiInterceptBasePort is the lowest loopback port the broker allocates
	// for a ziti-reach entry. Ports climb from here, one per enabled entry.
	pamZitiInterceptBasePort = 14000

	// pamZitiInterceptHost is the NON-loopback address the broker's ziti-tunnel
	// intercepts for every ziti-reach entry (one shared address, per-entry port).
	// It MUST NOT be a 127.0.0.0/8 loopback: ziti-edge-tunnel runs in TUN mode
	// and the kernel short-circuits loopback before it reaches the tun device, so
	// a 127.0.0.1 intercept never fires and guacd gets connection-refused. This
	// address lives in the tunnel's routed CIDR so it is captured and carried
	// over the overlay. The Guacamole connection host (dialTarget) and the
	// per-entry intercept.v1 config both use this value.
	pamZitiInterceptHost = "100.64.2.1"

	// pamZitiInterceptMaxPort bounds allocation so a runaway can't exhaust the
	// ephemeral range.
	pamZitiInterceptMaxPort = 14999
)

// pamZitiServiceName returns the per-entry Ziti service name.
func pamZitiServiceName(entryID string) string { return pamZitiServicePrefix + entryID }

// allocateLoopbackPort returns the lowest free port in [base, max] not present
// in used. Pure and deterministic so it is unit-testable. Returns 0 when the
// window is exhausted.
func allocateLoopbackPort(used []int, base, max int) int {
	taken := make(map[int]bool, len(used))
	for _, p := range used {
		taken[p] = true
	}
	for p := base; p <= max; p++ {
		if !taken[p] {
			return p
		}
	}
	return 0
}

// usedLoopbackPorts returns every assigned ziti_intercept_port across ALL orgs.
// The broker's ziti-tunnel is a single install-wide process, so ports are a
// global resource — allocation must see cross-org usage. Runs under bypass-RLS.
func (s *Service) usedLoopbackPorts(ctx context.Context) ([]int, error) {
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore broker loopback ports are an install-wide resource (single ziti-tunnel process); allocation must see all orgs
		`SELECT ziti_intercept_port FROM pam_entries WHERE ziti_intercept_port IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// provisionEntryZitiService creates the per-entry Ziti service, host.v1 config,
// Bind/Dial policies and service-edge-router policy for edge-router-hosted
// reach. Idempotent: re-running converges (get-or-create-or-update everywhere).
// Names follow the openidx-bind-/openidx-dial-/openidx-serp-/<svc>-host
// convention so TeardownZitiServiceByName reverses it.
func (s *Service) provisionEntryZitiService(ctx context.Context, zm *ZitiManager, serviceName, targetHost string, targetPort, interceptPort int) error {
	// 1. host.v1 config pinned to the target (edge router forwards straight to it).
	configID, err := zm.CreateHostV1ConfigFixed(ctx, serviceName+"-host", targetHost, targetPort)
	if err != nil {
		return fmt.Errorf("host.v1 config: %w", err)
	}

	// 1b. intercept.v1 config so the broker's ziti-tunnel captures the dial
	//     address (pamZitiInterceptHost:interceptPort) off its tun device and
	//     carries it over the overlay. Without this the tunnel has nothing to
	//     intercept and guacd's dial to that address is never captured.
	interceptID, err := zm.CreateInterceptV1ConfigFixed(ctx, serviceName+"-intercept", pamZitiInterceptHost, interceptPort)
	if err != nil {
		return fmt.Errorf("intercept.v1 config: %w", err)
	}

	// 2. Service carrying its own role attribute (#<serviceName>). Reuse if it
	//    already exists (a partially-applied prior enable) rather than dup-POST.
	zitiID, err := s.pamZitiServiceID(ctx, zm, serviceName)
	if err != nil {
		return err
	}
	if zitiID == "" {
		zitiID, err = zm.CreateService(ctx, serviceName, []string{serviceName, "openidx-managed", "openidx-pam"})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}

	// 3. Attach the host.v1 + intercept.v1 configs to the service.
	if err := zm.EnsureServiceConfig(ctx, zitiID, configID); err != nil {
		return fmt.Errorf("attach host config: %w", err)
	}
	if err := zm.EnsureServiceConfig(ctx, zitiID, interceptID); err != nil {
		return fmt.Errorf("attach intercept config: %w", err)
	}

	// 4. Bind → edge routers (they host the terminator to the target).
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-bind-"+serviceName, "Bind",
		[]string{"#" + serviceName}, []string{pamZitiRouterRole}); err != nil {
		return fmt.Errorf("bind policy: %w", err)
	}

	// 5. Dial → only the PAM broker's ziti-tunnel identity.
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-dial-"+serviceName, "Dial",
		[]string{"#" + serviceName}, []string{pamBrokerDialerRole}); err != nil {
		return fmt.Errorf("dial policy: %w", err)
	}

	// 6. Make the service available on all edge routers, and ensure routers carry
	//    the #ziti-routers role the Bind policy targets.
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+serviceName,
		[]string{"#" + serviceName}, []string{"#all"}); err != nil {
		return fmt.Errorf("service-edge-router policy: %w", err)
	}
	if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
		s.logger.Warn("provisionEntryZitiService: ensure router role attribute failed (non-fatal)", zap.Error(err))
	}

	// 7. Edge-router-policy granting the PAM broker's ziti-tunnel identity access
	//    to every edge router. Without it the tunnel has no online router for the
	//    service and dials fail with NO_EDGE_ROUTERS_AVAILABLE. Shared across all
	//    entries (idempotent name), so it converges regardless of enable order.
	if err := zm.EnsureEdgeRouterPolicy(ctx, "openidx-erp-pam-broker-dialers",
		[]string{"#all"}, []string{pamBrokerDialerRole}); err != nil {
		return fmt.Errorf("broker-dialers edge-router policy: %w", err)
	}
	return nil
}

// pamZitiServiceID looks up an existing service's ziti id by exact name via the
// name-filter endpoint (pagination-safe, unlike GetServiceByName). Returns ""
// when absent.
func (s *Service) pamZitiServiceID(ctx context.Context, zm *ZitiManager, serviceName string) (string, error) {
	path := fmt.Sprintf(`/edge/management/v1/services?filter=name="%s"`, serviceName)
	data, status, err := zm.mgmtRequest("GET", path, nil)
	if err != nil {
		return "", fmt.Errorf("lookup service: %w", err)
	}
	if status != http.StatusOK {
		return "", nil
	}
	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", nil
	}
	for _, d := range resp.Data {
		if d.Name == serviceName && d.ID != "" {
			return d.ID, nil
		}
	}
	return "", nil
}

// ---- Handlers ----

// handlePamEnableZiti — POST /pam/entries/:id/ziti/enable (admin).
// Provisions the overlay path for a launchable entry and flips it to ziti reach.
func (s *Service) handlePamEnableZiti(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	zm := s.ziti()
	if zm == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured", "code": "ziti_unconfigured"})
		return
	}

	var entryType, hostname, reachMode string
	var port int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT entry_type, COALESCE(hostname,''), COALESCE(port,0), reach_mode
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).
		Scan(&entryType, &hostname, &port, &reachMode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamEnableZiti: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}

	typeInfo, ok := pamEntryTypeByName[entryType]
	if !ok || typeInfo.Kind != "session" || typeInfo.Protocol == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ziti reach applies only to brokered session entries (rdp/ssh/vnc/telnet)"})
		return
	}
	if hostname == "" || port == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry needs a hostname and port before Ziti reach can be enabled"})
		return
	}
	if reachMode == "ziti" {
		c.JSON(http.StatusOK, gin.H{"id": entryID, "reach_mode": "ziti", "message": "already enabled"})
		return
	}

	// Allocate a globally-unique loopback port for the broker's ziti-tunnel.
	used, err := s.usedLoopbackPorts(ctx)
	if err != nil {
		s.logger.Error("handlePamEnableZiti: port scan failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to allocate broker port"})
		return
	}
	port2 := allocateLoopbackPort(used, pamZitiInterceptBasePort, pamZitiInterceptMaxPort)
	if port2 == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "no free broker loopback port available"})
		return
	}

	serviceName := pamZitiServiceName(entryID)
	if err := s.provisionEntryZitiService(ctx, zm, serviceName, hostname, port, port2); err != nil {
		s.logger.Error("handlePamEnableZiti: provisioning failed",
			zap.String("entry_id", scrubLogValue(entryID)), zap.Error(err))
		// Best-effort rollback of any partial provisioning.
		_ = zm.TeardownZitiServiceByName(ctx, serviceName)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to provision overlay service"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_entries
		   SET reach_mode = 'ziti', ziti_service_name = $1, ziti_intercept_port = $2, updated_at = NOW()
		 WHERE id = $3 AND org_id = $4`, serviceName, port2, entryID, org.ID)
	if err != nil || tag.RowsAffected() == 0 {
		// DB write failed after provisioning — tear the service back down so we
		// don't leak an unreferenced overlay service.
		_ = zm.TeardownZitiServiceByName(ctx, serviceName)
		s.logger.Error("handlePamEnableZiti: db update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable Ziti reach"})
		return
	}

	s.logAuditEvent(c, "pam.ziti_enabled", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "service_name": serviceName, "intercept_port": port2,
	})
	c.JSON(http.StatusOK, gin.H{
		"id": entryID, "reach_mode": "ziti",
		"ziti_service_name": serviceName, "ziti_intercept_port": port2,
	})
}

// handlePamDisableZiti — POST /pam/entries/:id/ziti/disable (admin).
// Tears down the overlay service and reverts the entry to direct reach.
func (s *Service) handlePamDisableZiti(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var reachMode, serviceName string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT reach_mode, COALESCE(ziti_service_name,'')
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).
		Scan(&reachMode, &serviceName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamDisableZiti: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}

	// Tear the overlay service down first (best-effort; the DB revert is the
	// source of truth for reach behaviour).
	if serviceName != "" {
		if zm := s.ziti(); zm != nil {
			if err := zm.TeardownZitiServiceByName(ctx, serviceName); err != nil {
				s.logger.Warn("handlePamDisableZiti: teardown failed (continuing)",
					zap.String("service", scrubLogValue(serviceName)), zap.Error(err))
			}
		} else {
			s.logger.Warn("handlePamDisableZiti: Ziti unavailable; reverting DB only, overlay service may linger",
				zap.String("service", scrubLogValue(serviceName)))
		}
	}

	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_entries
		   SET reach_mode = 'direct', ziti_service_name = NULL, ziti_intercept_port = NULL, updated_at = NOW()
		 WHERE id = $1 AND org_id = $2`, entryID, org.ID); err != nil {
		s.logger.Error("handlePamDisableZiti: db update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable Ziti reach"})
		return
	}

	s.logAuditEvent(c, "pam.ziti_disabled", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "service_name": serviceName,
	})
	c.JSON(http.StatusOK, gin.H{"id": entryID, "reach_mode": "direct"})
}

// PamZitiBinding is one service→loopback-port mapping the broker's ziti-tunnel
// consumes to know which local port proxies which overlay service.
type PamZitiBinding struct {
	ServiceName string `json:"service_name"`
	Port        int    `json:"port"`
}

// handlePamZitiBindings — GET /pam/broker/ziti-bindings (admin).
// Returns every ziti-enabled entry's {service_name, port} so the PAM broker's
// ziti-tunnel can be configured (proxy mode) to bind each loopback port to its
// service. Install-wide (the broker serves all orgs); runs under bypass-RLS.
func (s *Service) handlePamZitiBindings(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore broker binding list is install-wide (single ziti-tunnel serves all orgs); each row keyed by globally-unique service name/port
		`SELECT ziti_service_name, ziti_intercept_port
		  FROM pam_entries
		 WHERE reach_mode = 'ziti' AND ziti_service_name IS NOT NULL AND ziti_intercept_port IS NOT NULL
		 ORDER BY ziti_intercept_port`)
	if err != nil {
		s.logger.Error("handlePamZitiBindings: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list bindings"})
		return
	}
	defer rows.Close()

	bindings := []PamZitiBinding{}
	for rows.Next() {
		var b PamZitiBinding
		if err := rows.Scan(&b.ServiceName, &b.Port); err != nil {
			s.logger.Warn("handlePamZitiBindings: scan failed", zap.Error(err))
			continue
		}
		bindings = append(bindings, b)
	}
	c.JSON(http.StatusOK, gin.H{"bindings": bindings, "dialer_role": pamBrokerDialerRole})
}

// handlePamBrokerStatus — GET /pam/broker/status (any authenticated user).
// Capability probe so the launcher UI can explain a missing broker and show
// which reach modes are available, instead of dead-ending on a 503.
func (s *Service) handlePamBrokerStatus(c *gin.Context) {
	reachModes := []string{}
	directOK := s.guacamoleClient != nil
	// Ziti reach needs BOTH the dedicated Ziti broker (to render/relay the
	// session) and a live overlay (to provision/carry the target hop).
	zitiOK := s.guacamoleZitiClient != nil && s.ziti() != nil
	if directOK {
		reachModes = append(reachModes, "direct")
	}
	if zitiOK {
		reachModes = append(reachModes, "ziti")
	}
	sort.Strings(reachModes)
	c.JSON(http.StatusOK, gin.H{
		"available":     directOK || zitiOK,
		"reach_modes":   reachModes,
		"direct_broker": directOK,
		"ziti_broker":   zitiOK,
	})
}
