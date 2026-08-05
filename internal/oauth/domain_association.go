package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Domain-association files that bind the native OpenIDX mobile app to this
// domain. They are required for two things on real devices:
//   - Passkeys (WebAuthn): the OS only lets the app use a passkey whose RP ID is
//     this domain if the domain publishes the association for the app.
//   - Universal / App Links: OAuth redirect back into the app.
//
// Both are opt-in per deployment via config (WEBAUTHN_IOS_APP_ID,
// WEBAUTHN_ANDROID_PACKAGE, WEBAUTHN_ANDROID_SHA256). When the relevant values
// are unset the endpoint returns 404 so we never publish a placeholder that a
// device would try (and fail) to verify against.

// handleAppleAppSiteAssociation serves /.well-known/apple-app-site-association.
// The file must be served as application/json, without a redirect, over HTTPS.
func (s *Service) handleAppleAppSiteAssociation(c *gin.Context) {
	if s.config == nil || !s.config.WebAuthn.HasIOSAppAssociation() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_configured"})
		return
	}
	appID := s.config.WebAuthn.IOSAppID

	// webcredentials → passkeys; applinks → universal links back into the app.
	doc := gin.H{
		"webcredentials": gin.H{
			"apps": []string{appID},
		},
		"applinks": gin.H{
			"apps": []string{},
			"details": []gin.H{
				{
					"appID": appID,
					// Route only the OAuth callback path into the app; everything
					// else stays in the browser/console.
					"paths": []string{"/oauth-callback", "/oauth/*"},
				},
			},
		},
	}
	// Apple requires the exact content type and no caching surprises during setup.
	c.Header("Cache-Control", "public, max-age=3600")
	c.Header("Content-Type", "application/json")
	s.logger.Debug("Served apple-app-site-association", zap.String("app_id", appID))
	c.JSON(http.StatusOK, doc)
}

// handleAndroidAssetLinks serves /.well-known/assetlinks.json for Android App
// Links + Credential Manager (passkeys).
func (s *Service) handleAndroidAssetLinks(c *gin.Context) {
	if s.config == nil || !s.config.WebAuthn.HasAndroidAssetLinks() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_configured"})
		return
	}
	pkg := s.config.WebAuthn.AndroidPackage
	fp := s.config.WebAuthn.AndroidSHA256

	doc := []gin.H{
		{
			"relation": []string{
				"delegate_permission/common.handle_all_urls",
				"delegate_permission/common.get_login_creds",
			},
			"target": gin.H{
				"namespace":                "android_app",
				"package_name":             pkg,
				"sha256_cert_fingerprints": []string{fp},
			},
		},
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.Header("Content-Type", "application/json")
	s.logger.Debug("Served assetlinks.json", zap.String("package", pkg))
	c.JSON(http.StatusOK, doc)
}
