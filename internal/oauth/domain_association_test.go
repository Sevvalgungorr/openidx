package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// newAssocService builds a minimal Service carrying just the config the
// domain-association handlers read.
func newAssocService(wa config.WebAuthnConfig) *Service {
	return &Service{config: &config.Config{WebAuthn: wa}, logger: zap.NewNop()}
}

func TestAppleAppSiteAssociation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("404 when not configured", func(t *testing.T) {
		s := newAssocService(config.WebAuthnConfig{})
		r := gin.New()
		r.GET("/.well-known/apple-app-site-association", s.handleAppleAppSiteAssociation)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/apple-app-site-association", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", w.Code)
		}
	})

	t.Run("serves app id when configured", func(t *testing.T) {
		appID := "ABCDE12345.org.tdv.openidx"
		s := newAssocService(config.WebAuthnConfig{IOSAppID: appID})
		r := gin.New()
		r.GET("/.well-known/apple-app-site-association", s.handleAppleAppSiteAssociation)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/apple-app-site-association", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var doc struct {
			WebCredentials struct {
				Apps []string `json:"apps"`
			} `json:"webcredentials"`
			AppLinks struct {
				Details []struct {
					AppID string   `json:"appID"`
					Paths []string `json:"paths"`
				} `json:"details"`
			} `json:"applinks"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(doc.WebCredentials.Apps) != 1 || doc.WebCredentials.Apps[0] != appID {
			t.Errorf("webcredentials.apps = %v, want [%s]", doc.WebCredentials.Apps, appID)
		}
		if len(doc.AppLinks.Details) != 1 || doc.AppLinks.Details[0].AppID != appID {
			t.Errorf("applinks appID = %v, want %s", doc.AppLinks.Details, appID)
		}
	})
}

func TestAndroidAssetLinks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("404 without both package and fingerprint", func(t *testing.T) {
		for _, wa := range []config.WebAuthnConfig{
			{},
			{AndroidPackage: "org.tdv.openidx"}, // missing fingerprint
			{AndroidSHA256: "AA:BB:CC"},         // missing package
		} {
			s := newAssocService(wa)
			r := gin.New()
			r.GET("/.well-known/assetlinks.json", s.handleAndroidAssetLinks)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/assetlinks.json", nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("code = %d, want 404 for %+v", w.Code, wa)
			}
		}
	})

	t.Run("serves package + fingerprint when configured", func(t *testing.T) {
		pkg := "org.tdv.openidx"
		fp := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
		s := newAssocService(config.WebAuthnConfig{AndroidPackage: pkg, AndroidSHA256: fp})
		r := gin.New()
		r.GET("/.well-known/assetlinks.json", s.handleAndroidAssetLinks)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/assetlinks.json", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", w.Code)
		}
		var doc []struct {
			Relation []string `json:"relation"`
			Target   struct {
				Namespace    string   `json:"namespace"`
				PackageName  string   `json:"package_name"`
				Fingerprints []string `json:"sha256_cert_fingerprints"`
			} `json:"target"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(doc) != 1 {
			t.Fatalf("len = %d, want 1", len(doc))
		}
		if doc[0].Target.PackageName != pkg {
			t.Errorf("package = %q, want %q", doc[0].Target.PackageName, pkg)
		}
		if len(doc[0].Target.Fingerprints) != 1 || doc[0].Target.Fingerprints[0] != fp {
			t.Errorf("fingerprints = %v, want [%s]", doc[0].Target.Fingerprints, fp)
		}
		// Must include the passkey (get_login_creds) delegation, not just URLs.
		hasLoginCreds := false
		for _, rel := range doc[0].Relation {
			if rel == "delegate_permission/common.get_login_creds" {
				hasLoginCreds = true
			}
		}
		if !hasLoginCreds {
			t.Errorf("relation %v missing get_login_creds (passkeys won't bind)", doc[0].Relation)
		}
	})
}
