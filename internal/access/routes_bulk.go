package access

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// bulkRoute is one resource to expose via the proxy / overlay.
type bulkRoute struct {
	Name    string `json:"name"`
	FromURL string `json:"from_url"`
	ToURL   string `json:"to_url"`
	Ziti    bool   `json:"ziti"`
}

// subnetSpec expands a CIDR + port into one route per host — the "onboard a
// whole site/subnet" shortcut.
type subnetSpec struct {
	CIDR       string `json:"cidr"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"` // tcp (default) | http | https
	NamePrefix string `json:"name_prefix"`
	Ziti       bool   `json:"ziti"`
}

// expandSubnet turns a CIDR + port into per-host bulkRoutes. Capped at a /24
// (256 hosts) to prevent runaway provisioning; the network + broadcast
// addresses of prefixes /30 or shorter are skipped.
func expandSubnet(spec subnetSpec) ([]bulkRoute, error) {
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if spec.Port <= 0 || spec.Port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	prefix := strings.TrimSpace(spec.NamePrefix)
	if prefix == "" {
		prefix = "subnet"
	}
	ip, ipnet, err := net.ParseCIDR(spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 8 {
		return nil, fmt.Errorf("subnet too large (max /24 = 256 hosts)")
	}

	var hosts []net.IP
	for cur := ipnet.IP.Mask(ipnet.Mask).To4(); cur != nil && ipnet.Contains(cur); cur = nextIP(cur) {
		hosts = append(hosts, cloneIP(cur))
	}
	skipEnds := (bits - ones) >= 2 // /30 or shorter has a network + broadcast address

	var routes []bulkRoute
	for i, h := range hosts {
		if skipEnds && (i == 0 || i == len(hosts)-1) {
			continue
		}
		routes = append(routes, bulkRoute{
			Name:  fmt.Sprintf("%s-%s", prefix, h.String()),
			ToURL: fmt.Sprintf("%s://%s:%d", proto, h.String(), spec.Port),
			Ziti:  spec.Ziti,
		})
	}
	return routes, nil
}

func cloneIP(ip net.IP) net.IP { c := make(net.IP, len(ip)); copy(c, ip); return c }

func nextIP(ip net.IP) net.IP {
	c := cloneIP(ip)
	for i := len(c) - 1; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			return c
		}
	}
	return nil // overflowed the whole address space
}

// sanitizeZitiName reduces a display name to the Ziti-safe charset.
func sanitizeZitiName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

func routeTypeForURL(toURL string) string {
	l := strings.ToLower(toURL)
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
		return "http"
	}
	return "tcp"
}

// handleBulkRoutes creates many proxy_routes at once (an explicit list and/or a
// CIDR expansion), then asks the reconciler to converge — the "expand the
// network easily" endpoint. The reconciler creates all Ziti services/policies
// for the ziti-enabled rows on its next pass (routers already carry every
// service via the #all bootstrap, so no per-route policy edits are needed).
func (s *Service) handleBulkRoutes(c *gin.Context) {
	var req struct {
		Routes []bulkRoute `json:"routes"`
		Subnet *subnetSpec `json:"subnet"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	list := req.Routes
	if req.Subnet != nil {
		expanded, err := expandSubnet(*req.Subnet)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		list = append(list, expanded...)
	}
	if len(list) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no routes to create"})
		return
	}
	if len(list) > 512 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many routes in one request (max 512)"})
		return
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	created := 0
	for _, r := range list {
		name := strings.TrimSpace(r.Name)
		toURL := strings.TrimSpace(r.ToURL)
		if name == "" || toURL == "" {
			continue
		}
		svcName := ""
		if r.Ziti {
			svcName = "openidx-" + sanitizeZitiName(name)
		}
		if _, err := s.db.Pool.Exec(c.Request.Context(),
			`INSERT INTO proxy_routes (id, name, from_url, to_url, require_auth, enabled, priority,
			   route_type, ziti_enabled, ziti_service_name, hosting_mode, org_id)
			 VALUES ($1, $2, $3, $4, true, true, 10, $5, $6, $7, 'identity', $8)`,
			uuid.New().String(), name, strings.TrimSpace(r.FromURL), toURL,
			routeTypeForURL(toURL), r.Ziti, svcName, org.ID); err != nil {
			s.logger.Warn("bulk route insert failed", zap.String("name", name), zap.Error(err))
			continue
		}
		created++
	}
	if created > 0 {
		s.enqueueReconcile()
	}
	c.JSON(http.StatusOK, gin.H{"created": created, "requested": len(list)})
}

// handleRouterEnrollToken mints a new edge-router enrollment JWT and returns a
// copy-paste command to stand the router up — one-command site/gateway
// expansion. The router joins the mesh via the #all bootstrap with zero policy
// changes.
func (s *Service) handleRouterEnrollToken(c *gin.Context) {
	zm := s.ziti()
	if zm == nil || !zm.IsInitialized() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti controller not connected"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = c.ShouldBindJSON(&req)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "router-" + uuid.New().String()[:8]
	}

	id, jwt, err := zm.CreateEdgeRouter(c.Request.Context(), name, nil)
	if err != nil {
		s.logger.Error("router enroll-token: create failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to create edge router"})
		return
	}
	if jwt == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "router created but no enrollment token returned"})
		return
	}

	ctrl := ""
	if zm.cfg != nil {
		ctrl = zm.cfg.ZitiCtrlPublicAddress
	}
	// A ready-to-run one-liner: write the JWT to a file and enroll+run the
	// official router image against it. Generalizes deployments/apisix-edge/
	// ziti-router/setup-router-wss.sh into a single command.
	onboard := fmt.Sprintf(
		"docker run -d --name openidx-ziti-router --restart=always "+
			"-e ZITI_ENROLL_TOKEN='%s' -e ZITI_CTRL_ADVERTISED_ADDRESS='%s' "+
			"openziti/ziti-router:latest",
		jwt, ctrl)

	c.JSON(http.StatusOK, gin.H{
		"router_id":       id,
		"name":            name,
		"enrollment_jwt":  jwt,
		"controller":      ctrl,
		"onboard_command": onboard,
	})
}
