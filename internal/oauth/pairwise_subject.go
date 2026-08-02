package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// subjectFor returns the OIDC `sub` for a user as seen by one client.
//
// This is the whole of what survived internal/oauth/oidc.go. That file held an
// OIDCProvider with a parallel ID-token and UserInfo implementation that no
// route ever reached — /userinfo goes to Service.handleUserInfo — so it was
// removed. This function stayed because it is the opposite: it is on the live
// path, called from the ID token, UserInfo and the hybrid response builder.
//
// It exists at all because the live token path used to hardcode `sub: userID`
// while discovery advertised "pairwise" whenever OIDCPairwiseSubjects was set.
// An operator who turned the flag on to get pseudonymous subjects silently got
// none. Routing every caller through one function is what makes the advertised
// capability true.
//
// Pairwise = base64url(HMAC-SHA256(salt, clientID + "|" + userID)). The salt is
// the install's EncryptionKey, so the mapping is stable across restarts and not
// guessable by a relying party. The sector is the clientID
// (sector_identifier_uri grouping is not supported; per-client is the
// privacy-preserving default and still spec-valid).
//
// An empty clientID always yields the public subject, so a caller without
// client context never emits an unstable value.
func (s *Service) subjectFor(userID, clientID string) string {
	if clientID == "" || s == nil || s.config == nil || !s.config.OIDCPairwiseSubjects {
		return userID
	}
	mac := hmac.New(sha256.New, []byte(s.config.EncryptionKey))
	mac.Write([]byte(clientID + "|" + userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
