package access

import (
	"context"
	"fmt"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Loading upstream pools from the database.
//
// Kept separate from the rendering logic in upstream_pools.go so the mapping to
// the data plane stays testable without a database, and so the SQL here has one
// job: turn rows into the shape the renderer expects.

// loadUpstreamPools reads every pool (with members) for the reconciler.
//
// The reconciler renders desired state for all tenants at once, so this runs
// with RLS bypassed, exactly like the existing route query it feeds. Callers on
// a user request path must not use this; they go through the org-scoped admin
// handlers instead.
func (s *Service) loadUpstreamPools(ctx context.Context) (map[string]*UpstreamPool, error) {
	ctx = orgctx.WithBypassRLS(ctx)

	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide reconciler pass: renders desired upstream state for every org into the shared data plane, mirroring queryBrowZerRoutes
		`SELECT id, name, algorithm, hash_on, hash_key,
		        health_check_enabled, health_check_path,
		        healthy_threshold, unhealthy_threshold,
		        health_check_interval, health_check_timeout, retries
		 FROM upstream_pools`)
	if err != nil {
		return nil, fmt.Errorf("query upstream pools: %w", err)
	}
	defer rows.Close()

	pools := make(map[string]*UpstreamPool)
	for rows.Next() {
		var p UpstreamPool
		var retries *int
		if err := rows.Scan(&p.ID, &p.Name, &p.Algorithm, &p.HashOn, &p.HashKey,
			&p.HealthCheckEnabled, &p.HealthCheckPath,
			&p.HealthyThreshold, &p.UnhealthyThreshold,
			&p.HealthCheckInterval, &p.HealthCheckTimeout, &retries); err != nil {
			return nil, fmt.Errorf("scan upstream pool: %w", err)
		}
		p.Retries = retries
		pools[p.ID] = &p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(pools) == 0 {
		return pools, nil
	}

	mrows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide reconciler pass: members belong to the pools loaded above, which are already install-wide by design
		`SELECT pool_id, host, port, weight, enabled
		 FROM upstream_pool_members
		 ORDER BY host, port`)
	if err != nil {
		return nil, fmt.Errorf("query upstream pool members: %w", err)
	}
	defer mrows.Close()

	for mrows.Next() {
		var poolID string
		var m UpstreamMember
		if err := mrows.Scan(&poolID, &m.Host, &m.Port, &m.Weight, &m.Enabled); err != nil {
			return nil, fmt.Errorf("scan upstream pool member: %w", err)
		}
		if p, ok := pools[poolID]; ok {
			p.Members = append(p.Members, m)
		}
	}
	return pools, mrows.Err()
}

// LoadPoolForRender reads a single pool with its members.
//
// Exported so operator tooling can render exactly what the reconciler would
// render, rather than reimplementing the mapping and drifting from it. Runs
// with RLS bypassed for the same reason the reconciler does: it inspects
// desired state across the install.
func LoadPoolForRender(ctx context.Context, db *database.PostgresDB, poolID string) (*UpstreamPool, error) {
	ctx = orgctx.WithBypassRLS(ctx)

	var p UpstreamPool
	var retries *int
	err := db.Pool.QueryRow(ctx,
		//orgscope:ignore install-wide: renders desired upstream state, mirroring the reconciler's bypass
		`SELECT id, name, algorithm, hash_on, hash_key,
		        health_check_enabled, health_check_path,
		        healthy_threshold, unhealthy_threshold,
		        health_check_interval, health_check_timeout, retries
		 FROM upstream_pools WHERE id = $1`, poolID).
		Scan(&p.ID, &p.Name, &p.Algorithm, &p.HashOn, &p.HashKey,
			&p.HealthCheckEnabled, &p.HealthCheckPath,
			&p.HealthyThreshold, &p.UnhealthyThreshold,
			&p.HealthCheckInterval, &p.HealthCheckTimeout, &retries)
	if err != nil {
		return nil, fmt.Errorf("load pool %s: %w", poolID, err)
	}
	p.Retries = retries

	rows, err := db.Pool.Query(ctx,
		//orgscope:ignore install-wide: members of the pool loaded above
		`SELECT host, port, weight, enabled FROM upstream_pool_members
		 WHERE pool_id = $1 ORDER BY host, port`, poolID)
	if err != nil {
		return nil, fmt.Errorf("load pool members: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m UpstreamMember
		if err := rows.Scan(&m.Host, &m.Port, &m.Weight, &m.Enabled); err != nil {
			return nil, err
		}
		p.Members = append(p.Members, m)
	}
	return &p, rows.Err()
}
