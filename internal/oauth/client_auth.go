package oauth

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// Client authentication at the token endpoint.
//
// Discovery advertises both client_secret_post and client_secret_basic
// (token_endpoint_auth_methods_supported), but nothing ever parsed an
// Authorization: Basic header — every handler read client_id/client_secret from
// the form body only. A client following the advertised capability, or simply
// following RFC 6749 §2.3.1's "the authorization server MUST support the HTTP
// Basic authentication scheme", was rejected with invalid_client. That is the
// exact failure mode the codebase's own rule ("advertised = working") exists to
// prevent.

// clientCredentials extracts the client id and secret from a token-endpoint
// request, preferring the Authorization: Basic header over the form body.
//
// The second return value reports whether the request is well-formed. It is
// false only when the client used both mechanisms at once, which RFC 6749
// §2.3.1 forbids ("The client MUST NOT use more than one authentication method
// in each request") and which would otherwise leave the server silently
// choosing between two different credentials.
func clientCredentials(c *gin.Context) (id, secret string, ok bool) {
	basicID, basicSecret, hasBasic := basicClientAuth(c)
	formID, formSecret := c.PostForm("client_id"), c.PostForm("client_secret")

	if hasBasic {
		// A form client_id that merely repeats the Basic one is harmless and
		// common; a second *secret*, or a conflicting id, is the ambiguity the
		// RFC forbids.
		if formSecret != "" || (formID != "" && formID != basicID) {
			return "", "", false
		}
		return basicID, basicSecret, true
	}
	return formID, formSecret, true
}

// basicClientAuth decodes an Authorization: Basic header per RFC 6749 §2.3.1.
//
// The id and secret are form-urlencoded before base64 encoding, so they must be
// decoded on the way back out — a secret containing '+' or '%' is otherwise
// silently mangled into a mismatch that looks like a wrong password.
func basicClientAuth(c *gin.Context) (id, secret string, ok bool) {
	header := c.GetHeader("Authorization")
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}

	name, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}

	decodedName, err := url.QueryUnescape(name)
	if err != nil {
		return "", "", false
	}
	decodedPass, err := url.QueryUnescape(pass)
	if err != nil {
		return "", "", false
	}
	if decodedName == "" {
		return "", "", false
	}
	return decodedName, decodedPass, true
}
