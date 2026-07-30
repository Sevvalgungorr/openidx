package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/config"
)

func TestControllerEndpointPool(t *testing.T) {
	t.Run("primary must be valid", func(t *testing.T) {
		_, err := newControllerEndpointPool("not a url", "")
		assert.Error(t, err)
		_, err = newControllerEndpointPool("ftp://ctrl:1280", "")
		assert.Error(t, err)
	})

	t.Run("invalid and duplicate extras are dropped", func(t *testing.T) {
		p, err := newControllerEndpointPool("https://a:1280", "https://a:1280, nonsense,, https://b:1280/some/path")
		require.NoError(t, err)
		assert.Equal(t, 2, p.Size())
		snap := p.Snapshot()
		assert.Equal(t, "https://a:1280", snap[0].URL)
		// Path is stripped — pool stores scheme://host only (SSRF guard parity).
		assert.Equal(t, "https://b:1280", snap[1].URL)
	})

	t.Run("failover and cooldown recovery", func(t *testing.T) {
		p, err := newControllerEndpointPool("https://a:1280", "https://b:1280,https://c:1280")
		require.NoError(t, err)
		now := time.Now()
		p.now = func() time.Time { return now }

		assert.Equal(t, "https://a:1280", p.Current())

		next, changed := p.MarkDown("https://a:1280")
		assert.True(t, changed)
		assert.Equal(t, "https://b:1280", next)
		assert.Equal(t, "https://b:1280", p.Current())

		next, changed = p.MarkDown("https://b:1280")
		assert.True(t, changed)
		assert.Equal(t, "https://c:1280", next)

		// All down → stick with the active endpoint rather than erroring.
		_, changed = p.MarkDown("https://c:1280")
		assert.False(t, changed)
		assert.Equal(t, "https://c:1280", p.Current())

		// After the cooldown the active endpoint is eligible again; selection
		// is sticky (no failback churn), so the pool stays on it.
		now = now.Add(zitiEndpointCooldown + time.Second)
		assert.Equal(t, "https://c:1280", p.Current())

		// Only when the active member fails again does a recovered earlier
		// member take over.
		next, changed = p.MarkDown("https://c:1280")
		assert.True(t, changed)
		assert.Equal(t, "https://a:1280", next)
	})

	t.Run("mark up makes an endpoint eligible without forcing failback", func(t *testing.T) {
		p, err := newControllerEndpointPool("https://a:1280", "https://b:1280")
		require.NoError(t, err)
		p.MarkDown("https://a:1280")
		assert.Equal(t, "https://b:1280", p.Current())
		// Recovery is sticky: a becomes eligible but b keeps serving...
		p.MarkUp("https://a:1280")
		assert.Equal(t, "https://b:1280", p.Current())
		// ...until b itself fails, at which point a takes over instantly.
		next, changed := p.MarkDown("https://b:1280")
		assert.True(t, changed)
		assert.Equal(t, "https://a:1280", next)
	})

	t.Run("single endpoint pool never rotates", func(t *testing.T) {
		p, err := newControllerEndpointPool("https://a:1280", "")
		require.NoError(t, err)
		next, changed := p.MarkDown("https://a:1280")
		assert.False(t, changed)
		assert.Equal(t, "https://a:1280", next)
	})
}

// newFakeController returns an httptest controller that answers password auth
// and a version request, optionally failing every request with 503.
func newFakeController(t *testing.T, failing *atomic.Bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/management/v1/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if failing != nil && failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"token": "tok-" + r.Host}})
	})
	mux.HandleFunc("/edge/management/v1/version", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failing != nil && failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": "v1.6.12"}})
	})
	return httptest.NewServer(mux), &hits
}

func TestMgmtRequestFailsOverToHealthyController(t *testing.T) {
	var aFailing atomic.Bool
	primary, primaryHits := newFakeController(t, &aFailing)
	defer primary.Close()
	secondary, secondaryHits := newFakeController(t, nil)
	defer secondary.Close()

	cfg := &config.Config{
		ZitiCtrlURL:  primary.URL,
		ZitiCtrlURLs: secondary.URL,
	}
	pool, err := newControllerEndpointPool(cfg.ZitiCtrlURL, cfg.ZitiCtrlURLs)
	require.NoError(t, err)

	zm := &ZitiManager{
		cfg:        cfg,
		logger:     MockLogger(t),
		mgmtClient: &http.Client{Timeout: 2 * time.Second},
		pool:       pool,
	}
	require.NoError(t, zm.authenticate())

	// Healthy primary serves the request.
	_, status, err := zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, int32(1), primaryHits.Load())

	// Primary starts failing → the same call transparently lands on the
	// secondary after a fresh auth there.
	aFailing.Store(true)
	_, status, err = zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, int32(1), secondaryHits.Load())

	// Subsequent calls go straight to the secondary while the primary cools
	// down — no repeated probing of the dead member.
	_, status, err = zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, int32(2), secondaryHits.Load())
	assert.Equal(t, int32(2), primaryHits.Load()) // only the initial hit + the failed one

	// Status surface reflects the failover.
	eps := zm.ControllerEndpoints()
	require.Len(t, eps, 2)
	assert.False(t, eps[0].Healthy)
	assert.True(t, eps[1].Active)
}

func TestMgmtRequestFailsOverOnConnectionRefused(t *testing.T) {
	secondary, secondaryHits := newFakeController(t, nil)
	defer secondary.Close()

	// A dead primary: reserve a port then close it so dials are refused.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	cfg := &config.Config{ZitiCtrlURL: deadURL, ZitiCtrlURLs: secondary.URL}
	pool, err := newControllerEndpointPool(cfg.ZitiCtrlURL, cfg.ZitiCtrlURLs)
	require.NoError(t, err)

	zm := &ZitiManager{
		cfg:        cfg,
		logger:     MockLogger(t),
		mgmtClient: &http.Client{Timeout: 2 * time.Second},
		pool:       pool,
	}

	// Auth itself must fail over to the live member.
	require.NoError(t, zm.authenticate())

	_, status, err := zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.GreaterOrEqual(t, secondaryHits.Load(), int32(1))
}

func TestMgmtRequestSingleEndpointBehaviorUnchanged(t *testing.T) {
	var failing atomic.Bool
	ctrl, _ := newFakeController(t, &failing)
	defer ctrl.Close()

	cfg := &config.Config{ZitiCtrlURL: ctrl.URL}
	pool, err := newControllerEndpointPool(cfg.ZitiCtrlURL, "")
	require.NoError(t, err)
	zm := &ZitiManager{
		cfg:        cfg,
		logger:     MockLogger(t),
		mgmtClient: &http.Client{Timeout: 2 * time.Second},
		pool:       pool,
	}
	require.NoError(t, zm.authenticate())

	failing.Store(true)
	_, status, err := zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	require.NoError(t, err)
	// No second endpoint → the 503 is returned to the caller as before.
	assert.Equal(t, http.StatusServiceUnavailable, status)
}
