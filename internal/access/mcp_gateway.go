package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// MCP / AI-agent gateway (Wave D1). An AI agent authenticates with an
// OpenIDX-issued token; every MCP tool call goes through this gateway, which
// authenticates the agent, checks a per-tool allowlist, forwards to the MCP
// server (a dark Ziti service or a URL), and audits the call. Network-enforced
// agent containment: pure-IdP rivals can gate the token but not the packet.

// MCPServer is a registered MCP server.
type MCPServer struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	ZitiService string    `json:"ziti_service,omitempty"`
	UpstreamURL string    `json:"upstream_url,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MCPServerInput is the create payload.
type MCPServerInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ZitiService string `json:"ziti_service,omitempty"`
	UpstreamURL string `json:"upstream_url,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// MCPToolPolicyInput grants a principal access to a tool (or '*').
type MCPToolPolicyInput struct {
	Principal string `json:"principal"` // client:<id> | role:<name>
	Tool      string `json:"tool,omitempty"`
}

func mcpOrgID(c *gin.Context) string {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		return ""
	}
	return org.ID
}

// --- server + policy store ---

func (s *Service) CreateMCPServer(ctx context.Context, orgID string, in *MCPServerInput) (*MCPServer, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if in.ZitiService == "" && in.UpstreamURL == "" {
		return nil, fmt.Errorf("one of ziti_service or upstream_url is required")
	}
	id := uuid.NewString()
	_, err := s.db.Pool.Exec(ctx, `
        INSERT INTO mcp_servers (id, org_id, name, description, ziti_service, upstream_url, enabled)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, mcpNullIfEmpty(orgID), in.Name, mcpNullIfEmpty(in.Description),
		mcpNullIfEmpty(in.ZitiService), mcpNullIfEmpty(in.UpstreamURL), in.Enabled)
	if err != nil {
		return nil, fmt.Errorf("insert mcp server: %w", err)
	}
	return s.getMCPServerByID(ctx, orgID, id)
}

func (s *Service) getMCPServerByID(ctx context.Context, orgID, id string) (*MCPServer, error) {
	row := s.db.Pool.QueryRow(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, COALESCE(description,''),
               COALESCE(ziti_service,''), COALESCE(upstream_url,''), enabled, created_at, updated_at
          FROM mcp_servers WHERE id=$1 AND (org_id::text=$2 OR $2='')`, id, orgID)
	return scanMCPServer(row)
}

func (s *Service) getMCPServerByName(ctx context.Context, orgID, name string) (*MCPServer, error) {
	row := s.db.Pool.QueryRow(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, COALESCE(description,''),
               COALESCE(ziti_service,''), COALESCE(upstream_url,''), enabled, created_at, updated_at
          FROM mcp_servers WHERE name=$1 AND (org_id::text=$2 OR $2='') AND enabled`, name, orgID)
	return scanMCPServer(row)
}

func (s *Service) ListMCPServers(ctx context.Context, orgID string) ([]MCPServer, error) {
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, COALESCE(description,''),
               COALESCE(ziti_service,''), COALESCE(upstream_url,''), enabled, created_at, updated_at
          FROM mcp_servers WHERE (org_id::text=$1 OR $1='') ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPServer
	for rows.Next() {
		srv, err := scanMCPServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *srv)
	}
	return out, rows.Err()
}

func (s *Service) DeleteMCPServer(ctx context.Context, orgID, id string) error {
	ct, err := s.db.Pool.Exec(ctx,
		`DELETE FROM mcp_servers WHERE id=$1 AND (org_id::text=$2 OR $2='')`, id, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("mcp server not found")
	}
	return nil
}

func (s *Service) AddMCPToolPolicy(ctx context.Context, orgID, serverID string, in *MCPToolPolicyInput) error {
	if in.Principal == "" {
		return fmt.Errorf("principal is required")
	}
	tool := in.Tool
	if tool == "" {
		tool = "*"
	}
	_, err := s.db.Pool.Exec(ctx, `
        INSERT INTO mcp_tool_policies (org_id, server_id, principal, tool)
        VALUES ($1,$2,$3,$4) ON CONFLICT (server_id, principal, tool) DO NOTHING`,
		mcpNullIfEmpty(orgID), serverID, in.Principal, tool)
	return err
}

// toolAllowed reports whether a principal set (the agent client_id + its roles)
// is permitted to invoke tool on serverID. A '*' tool policy is a server-wide
// grant.
func (s *Service) toolAllowed(ctx context.Context, serverID, clientID string, roles []string, tool string) bool {
	principals := []string{"client:" + clientID}
	for _, r := range roles {
		principals = append(principals, "role:"+r)
	}
	var allowed bool
	if err := s.db.Pool.QueryRow(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM mcp_tool_policies
             WHERE server_id = $1 AND principal = ANY($2)
               AND (tool = $3 OR tool = '*'))`,
		serverID, principals, tool).Scan(&allowed); err != nil {
		return false
	}
	return allowed
}

// --- gateway ---

// handleMCPInvoke is the gateway: POST /api/v1/mcp/:server/tools/:tool.
// The agent's OpenIDX token authenticates it; a per-tool allowlist gates the
// call; the request forwards to the MCP server (dark Ziti service or URL); the
// call is audited.
func (s *Service) handleMCPInvoke(c *gin.Context) {
	serverName := c.Param("server")
	tool := c.Param("tool")

	// 1. Authenticate the agent from its bearer token.
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := middleware.VerifyBearerToken(s.oauthJWKSURL, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	clientID, _ := claims["client_id"].(string)
	subject, _ := claims["sub"].(string)
	roles := claimStrings(claims["roles"])

	// 2. Resolve the MCP server.
	orgID := mcpOrgID(c)
	server, err := s.getMCPServerByName(c.Request.Context(), orgID, serverName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "mcp server not found"})
		return
	}

	// 3. Per-tool allowlist.
	if !s.toolAllowed(c.Request.Context(), server.ID, clientID, roles, tool) {
		s.auditMCP(c.Request.Context(), clientID, subject, server.Name, tool, "denied")
		c.JSON(http.StatusForbidden, gin.H{"error": "tool not permitted for this agent"})
		return
	}

	// 4. Forward to the MCP server.
	body, _ := io.ReadAll(io.LimitReader(c.Request.Body, 8<<20))

	// 4a. HITL approval gate (PAM C5): sensitive tools wait for a human. When
	// approval is required and not yet granted, gateToolCall writes the 202
	// response and we stop here; the agent retries the identical call once
	// approved.
	proceed, gerr := s.gateToolCall(c.Request.Context(), c, mcpApprovalContext{
		OrgID: orgID, ServerID: server.ID, Server: server.Name,
		Tool: tool, ClientID: clientID, Subject: subject,
	}, roles, body)
	if gerr != nil {
		s.logger.Error("handleMCPInvoke: approval gate failed", zap.Error(gerr))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "approval gate error"})
		return
	}
	if !proceed {
		return
	}

	status, respBody, ferr := s.forwardMCP(c.Request.Context(), server, tool, body)
	if ferr != nil {
		s.auditMCP(c.Request.Context(), clientID, subject, server.Name, tool, "error")
		c.JSON(http.StatusBadGateway, gin.H{"error": "mcp forward failed", "detail": ferr.Error()})
		return
	}
	s.auditMCP(c.Request.Context(), clientID, subject, server.Name, tool, "allowed")
	c.Data(status, "application/json", respBody)
}

// forwardMCP dials the MCP server (over Ziti when ziti_service is set, else the
// URL) and POSTs the tool invocation.
func (s *Service) forwardMCP(ctx context.Context, server *MCPServer, tool string, body []byte) (int, []byte, error) {
	var client *http.Client
	var target string
	if server.ZitiService != "" {
		zm := s.ziti()
		if zm == nil {
			return 0, nil, fmt.Errorf("overlay not active; cannot reach dark mcp service")
		}
		client = &http.Client{Transport: zm.ZitiTransport(server.ZitiService), Timeout: 30 * time.Second}
		// The Ziti transport dials by service name; the host in the URL is
		// cosmetic. Route to the tool path on the server.
		target = "http://" + server.ZitiService + "/tools/" + tool
	} else {
		client = &http.Client{Timeout: 30 * time.Second}
		target = strings.TrimRight(server.UpstreamURL, "/") + "/tools/" + tool
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, out, nil
}

// auditMCP records an MCP tool call in unified_audit_events.
func (s *Service) auditMCP(ctx context.Context, clientID, subject, server, tool, outcome string) {
	details, _ := json.Marshal(map[string]interface{}{
		"client_id": clientID, "server": server, "tool": tool, "outcome": outcome,
	})
	//orgscope:ignore MCP gateway audit; agent identity is the OAuth client_id/subject on the token, not an org-scoped row
	_, _ = s.db.Pool.Exec(ctx, `
        INSERT INTO unified_audit_events (id, source, event_type, user_id, details, created_at)
        VALUES (gen_random_uuid(), 'mcp', $1, NULLIF($2,'')::uuid, $3, NOW())`,
		"mcp.tool."+outcome, subject, details)
}

// --- helpers ---

func mcpNullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func claimStrings(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type mcpRowScanner interface {
	Scan(dest ...interface{}) error
}

func scanMCPServer(row mcpRowScanner) (*MCPServer, error) {
	var m MCPServer
	if err := row.Scan(&m.ID, &m.OrgID, &m.Name, &m.Description,
		&m.ZitiService, &m.UpstreamURL, &m.Enabled, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	return &m, nil
}
