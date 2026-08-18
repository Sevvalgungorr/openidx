package access

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// agentDownloadsDir is the directory holding per-OS agent installers (msi/pkg/
// deb/rpm). Configurable via AGENT_DOWNLOADS_DIR.
func (h *AgentAPIHandler) agentDownloadsDir() string {
	if c := h.cfg(); c != nil && strings.TrimSpace(c.AgentDownloadsDir) != "" {
		return c.AgentDownloadsDir
	}
	return "deployments/downloads"
}

// osForInstaller maps an installer filename extension to a wizard OS key, or "".
func osForInstaller(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".msi", ".exe":
		return "windows"
	case ".pkg", ".dmg":
		return "macos"
	case ".deb", ".rpm":
		return "linux"
	case ".apk":
		return "android"
	}
	return ""
}

// downloadNameRe rejects anything but a bare filename (no path traversal).
var downloadNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// HandleAgentDownload backs GET /downloads/:file (public, no auth — like the
// legacy APK route it replaces). It dispatches the manifest, the Android APK,
// and per-OS installers from the downloads dir. Using one param route avoids a
// gin static-vs-wildcard conflict at /downloads/*.
func (h *AgentAPIHandler) HandleAgentDownload(c *gin.Context) {
	name := c.Param("file")
	switch name {
	case "agent-manifest.json":
		h.handleAgentManifest(c)
		return
	case "openidx-agent.apk":
		h.HandleAPKDownload(c)
		return
	}
	if !downloadNameRe.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}
	full := filepath.Join(h.agentDownloadsDir(), name)
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.FileAttachment(full, name)
}

// handleAgentManifest advertises the available per-OS installers so the
// Add-a-device wizard can render a download button. Keys are wizard OS keys
// (windows/macos/linux/android); missing OSes are simply omitted.
func (h *AgentAPIHandler) handleAgentManifest(c *gin.Context) {
	out := map[string]gin.H{}
	dir := h.agentDownloadsDir()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		osKey := osForInstaller(e.Name())
		if osKey == "" {
			continue
		}
		if _, seen := out[osKey]; seen {
			continue
		}
		sum, _ := sha256File(filepath.Join(dir, e.Name()))
		out[osKey] = gin.H{"url": "/downloads/" + e.Name(), "filename": e.Name(), "sha256": sum}
	}
	// The Android APK historically lives at its own path; surface it if present
	// and not already provided by the downloads dir.
	if _, ok := out["android"]; !ok {
		if _, err := os.Stat(androidAPKPath); err == nil {
			sum, _ := sha256File(androidAPKPath)
			out["android"] = gin.H{"url": "/downloads/openidx-agent.apk", "filename": "openidx-agent.apk", "sha256": sum}
		}
	}
	c.JSON(http.StatusOK, out)
}

// sha256File returns the hex SHA-256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hsh := sha256.New()
	if _, err := io.Copy(hsh, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hsh.Sum(nil)), nil
}
