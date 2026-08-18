package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func newDownloadHandler(t *testing.T, dir string) *AgentAPIHandler {
	t.Helper()
	return &AgentAPIHandler{
		logger: zap.NewNop(),
		zm:     &ZitiManager{cfg: &config.Config{AgentDownloadsDir: dir}},
	}
}

func TestAgentManifestAndDownload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	for _, f := range []string{"openidx-agent.msi", "openidx-agent.pkg", "openidx-agent-linux-amd64.deb"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("installer-"+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newDownloadHandler(t, dir)

	// Manifest advertises one entry per OS with url + sha256.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "agent-manifest.json"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent-manifest.json", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", w.Code)
	}
	var m map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	for _, os := range []string{"windows", "macos", "linux"} {
		if m[os]["url"] == "" || m[os]["sha256"] == "" {
			t.Errorf("manifest missing %s: %+v", os, m[os])
		}
	}
	if m["windows"]["url"] != "/downloads/openidx-agent.msi" {
		t.Errorf("windows url = %q", m["windows"]["url"])
	}

	// A real file downloads.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "openidx-agent.pkg"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/openidx-agent.pkg", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusOK || w.Body.String() != "installer-openidx-agent.pkg" {
		t.Errorf("download = %d %q", w.Code, w.Body.String())
	}

	// Path-traversal / bad names are rejected.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "../secret"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/x", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("traversal not rejected: %d", w.Code)
	}

	// Missing file → 404.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "nope.deb"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/nope.deb", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing file status = %d", w.Code)
	}
}
