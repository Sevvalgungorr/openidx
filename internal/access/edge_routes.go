package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// Rendering ordinary (non-BrowZer) routes into the edge, with pool support.
//
// The BrowZer reconciler renders its own routes because they all terminate at
// the bootstrapper. Everything else is a plain "this hostname goes to that
// backend" route, and that is where an upstream pool becomes meaningful: the
// single to_url grows into a weighted, health-checked set.
//
// Routes without a pool keep rendering exactly as before, from to_url. That is
// what makes pools opt-in and this change safe to run against a live edge.

// edgeRoute is one row of desired edge state.
type edgeRoute struct {
	name     string
	fromURL  string
	toURL    string
	poolID   string // empty when the route uses to_url
	priority int
}

// hostFromURL extracts the hostname a client connects to.
func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// upstreamFromToURL renders the pre-pool behaviour: a single node taken from
// to_url. Kept as its own function so the fallback path is explicit rather than
// an accident of an empty pool.
func upstreamFromToURL(raw string) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("route target %q is not a usable URL", raw)
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("route target %q has a bad port", raw)
	}
	return map[string]interface{}{
		"type":   "roundrobin",
		"scheme": scheme,
		"nodes":  map[string]interface{}{fmt.Sprintf("%s:%d", u.Hostname(), p): 1},
	}, nil
}

// buildEdgeRoute renders one route, using its pool when it has a usable one.
//
// A route that names a pool which cannot serve traffic (every member drained or
// disabled) falls back to to_url rather than rendering an empty upstream. The
// alternative would silently black-hole the route, which is a worse outcome
// than "the pool is not in effect yet".
func buildEdgeRoute(r edgeRoute, pools map[string]*UpstreamPool, logger *zap.Logger) (name string, body []byte, err error) {
	host := hostFromURL(r.fromURL)
	if host == "" {
		return "", nil, fmt.Errorf("route %q has no usable hostname in %q", r.name, r.fromURL)
	}

	var upstream map[string]interface{}
	if r.poolID != "" {
		if pool, ok := pools[r.poolID]; ok {
			scheme := "http"
			if u, perr := url.Parse(r.toURL); perr == nil && u.Scheme != "" {
				scheme = u.Scheme
			}
			upstream, err = pool.BuildUpstream(scheme, "", "")
			if err != nil && logger != nil {
				logger.Warn("upstream pool unusable; falling back to the route's single target",
					zap.String("route", r.name), zap.String("pool", pool.Name), zap.Error(err))
			}
		} else if logger != nil {
			logger.Warn("route names an unknown upstream pool; falling back to its single target",
				zap.String("route", r.name), zap.String("pool_id", r.poolID))
		}
	}
	if upstream == nil {
		upstream, err = upstreamFromToURL(r.toURL)
		if err != nil {
			return "", nil, err
		}
	}

	obj := map[string]interface{}{
		"name":             edgeRouteName(r.name),
		"hosts":            []string{host},
		"uri":              "/*",
		"priority":         r.priority,
		"enable_websocket": true,
		"upstream":         upstream,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", nil, err
	}
	return edgeRouteName(r.name), b, nil
}

// edgeRouteName namespaces generated routes so a reconcile pass can tell its
// own objects apart from hand-made ones and never prune somebody else's.
func edgeRouteName(routeName string) string {
	slug := apisixSlug(routeName)
	if slug == "" {
		slug = "unnamed"
	}
	return "oidx-route-" + slug
}

// queryEdgeRoutes reads the routes that should exist at the edge.
//
// BrowZer-enabled routes are excluded: they are rendered by the BrowZer
// reconciler, which points them at the bootstrapper instead of the backend.
func (s *Service) queryEdgeRoutes(ctx context.Context) ([]edgeRoute, error) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide reconciler pass: renders desired edge state for every org into the shared data plane, mirroring queryBrowZerRoutes
		`SELECT name, from_url, to_url, COALESCE(upstream_pool_id::text, ''), COALESCE(priority, 0)
		 FROM proxy_routes
		 WHERE enabled = true
		   AND COALESCE(browzer_enabled, false) = false
		 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("query edge routes: %w", err)
	}
	defer rows.Close()

	var out []edgeRoute
	for rows.Next() {
		var r edgeRoute
		if err := rows.Scan(&r.name, &r.fromURL, &r.toURL, &r.poolID, &r.priority); err != nil {
			return nil, fmt.Errorf("scan edge route: %w", err)
		}
		// A route whose from_url is not a real hostname cannot be served; skip
		// it here rather than failing the whole pass.
		if strings.TrimSpace(r.fromURL) == "" || hostFromURL(r.fromURL) == "" {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BuildEdgeRoutesForPools renders every pool-backed route.
//
// Only routes that actually name a pool are rendered here. Routes still on
// to_url are left to whatever already serves them, so enabling this path cannot
// disturb the existing edge configuration.
func (s *Service) BuildEdgeRoutesForPools(ctx context.Context) ([]apisixRoute, error) {
	pools, err := s.loadUpstreamPools(ctx)
	if err != nil {
		return nil, err
	}
	if len(pools) == 0 {
		return nil, nil
	}

	routes, err := s.queryEdgeRoutes(ctx)
	if err != nil {
		return nil, err
	}

	var out []apisixRoute
	for _, r := range routes {
		if r.poolID == "" {
			continue
		}
		name, body, err := buildEdgeRoute(r, pools, s.logger)
		if err != nil {
			s.logger.Warn("skipping route that cannot be rendered",
				zap.String("route", r.name), zap.Error(err))
			continue
		}
		out = append(out, apisixRoute{name: name, body: body})
	}
	return out, nil
}
