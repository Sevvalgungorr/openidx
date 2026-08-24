// Package updater implements cross-platform self-update: poll a version
// manifest, and when a newer signed artifact is published, download it
// (checksum-verified) and apply it with the platform-appropriate installer —
// msiexec on Windows, `installer` for a macOS .pkg, dpkg/rpm for Linux packages,
// or an atomic executable self-replace + re-exec for a bare binary/AppImage. The
// manifest URL is configured per-install; empty disables auto-update.
//
// Manifest format (JSON) — the url's file extension selects the install method:
//
//	{ "version": "1.2.0",
//	  "url": "https://.../OpenIDX-1.2.0.msi",   // or .pkg/.deb/.rpm/.AppImage/bare
//	  "sha256": "<hex>" }
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Manifest describes the latest published release.
type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Fetch retrieves and parses the version manifest.
func Fetch(ctx context.Context, manifestURL string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest returned %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Version == "" || m.URL == "" {
		return nil, fmt.Errorf("manifest missing version/url")
	}
	return &m, nil
}

// Newer reports whether candidate is a strictly higher version than current.
// Compares dot/dash-separated numeric segments; a non-numeric current (e.g.
// "dev") is always considered older.
func Newer(current, candidate string) bool {
	if current == "dev" || current == "" {
		return true
	}
	return compare(segments(candidate), segments(current)) > 0
}

func segments(v string) []int {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' })
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, ok := 0, len(p) > 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				ok = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if !ok {
			break
		}
		nums = append(nums, n)
	}
	return nums
}

func compare(a, b []int) int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// artifactExt returns the download URL's file extension (lowercased, with the
// leading dot), which selects the install method. Query/fragment suffixes are
// stripped first; a URL with no extension yields ".bin" (treated as a bare
// binary for self-replace).
func artifactExt(url string) string {
	u := url
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	ext := strings.ToLower(filepath.Ext(u))
	if ext == "" {
		return ".bin"
	}
	return ext
}

// downloadVerified downloads url to a temp file and verifies its SHA-256 (when
// the manifest provides one). Returns the temp file path (caller removes it).
func downloadVerified(ctx context.Context, url, wantSHA string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "openidx-update-*"+artifactExt(url))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()

	if wantSHA != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, strings.TrimSpace(wantSHA)) {
			os.Remove(f.Name())
			return "", fmt.Errorf("checksum mismatch: got %s want %s", got, wantSHA)
		}
	}
	return f.Name(), nil
}

// CheckAndApply fetches the manifest; if it advertises a newer version than
// currentVersion, downloads (checksum-verified) and applies the MSI. Returns
// whether an update was applied and the new version.
func CheckAndApply(ctx context.Context, manifestURL, currentVersion string) (applied bool, newVersion string, err error) {
	m, err := Fetch(ctx, manifestURL)
	if err != nil {
		return false, "", err
	}
	if !Newer(currentVersion, m.Version) {
		return false, m.Version, nil
	}
	path, err := downloadVerified(ctx, m.URL, m.SHA256)
	if err != nil {
		return false, m.Version, err
	}
	// Move the artifact to a stable, predictable temp path before applying: the
	// Windows msiexec path runs asynchronously, and a self-replace reads it as
	// the new binary.
	stable := filepath.Join(os.TempDir(), "OpenIDX-"+m.Version+artifactExt(m.URL))
	_ = os.Rename(path, stable)
	if err := apply(stable); err != nil {
		return false, m.Version, err
	}
	return true, m.Version, nil
}
