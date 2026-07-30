// Package access — PAM B4: cloud console/CLI just-in-time (JIT) elevation.
//
// Instead of standing IAM users or long-lived access keys, an operator asks
// OpenIDX to broker SHORT-LIVED cloud access. OpenIDX calls STS AssumeRole with
// the org's broker credentials (held envelope-encrypted in the vault), gets
// temporary credentials scoped to the target role, and returns:
//
//   - the temporary access key / secret / session token for native CLI/SDK use;
//   - a federated AWS console sign-in URL (getSigninToken) so the operator can
//     click straight into a time-boxed console session.
//
// Revocation is automatic: STS temporary credentials expire at the requested
// TTL, so there is nothing to clean up and no standing privilege. Every
// issuance is recorded in brokered_sessions (target_type='cloud') — the same
// ledger that covers SSH/DB/K8s brokering — and audited.
//
// This is the AWS provider; the handler is structured so GCP/Azure equivalents
// (STS-like short-lived tokens) can slot in behind the same endpoint later.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	cloudJITDefaultTTL = 60 * time.Minute
	cloudJITMaxTTL     = 12 * time.Hour
	cloudJITMinTTL     = 15 * time.Minute
)

// assumeRoleAPI is the subset of the STS client used here. An interface so
// tests can substitute a fake without network access.
type assumeRoleAPI interface {
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// newAssumeRoleClient builds a real STS client from broker credentials. Package
// var so tests can swap in a fake.
var newAssumeRoleClient = func(region, accessKeyID, secretAccessKey string) assumeRoleAPI {
	return sts.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: awscreds.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	})
}

// federationSigninURL is the endpoint used to exchange a temporary session for
// a console sign-in token, and the console destination. Package vars so tests
// can point at a mock server.
var (
	awsFederationEndpoint = "https://signin.aws.amazon.com/federation"
	awsConsoleDestination = "https://console.aws.amazon.com/"
	cloudJITHTTPClient    = &http.Client{Timeout: 15 * time.Second}
)

// cloudConnectReq is the JIT elevation request.
type cloudConnectReq struct {
	Provider   string `json:"provider"`    // "aws" (default). GCP/Azure reserved.
	RoleARN    string `json:"role_arn"`    // role to assume (required for aws)
	Region     string `json:"region"`      // defaults us-east-1
	SecretID   string `json:"secret_id"`   // vault secret holding broker creds (JSON access_key_id/secret_access_key)
	Reason     string `json:"reason"`      // audited
	TTLMinutes int    `json:"ttl_minutes"` // clamped to [15, 720]
	Console    bool   `json:"console"`     // also return a federated console URL
}

// handleCloudConnect — POST /pam/connect/cloud. Brokers short-lived cloud
// credentials via STS AssumeRole and (optionally) a federated console URL.
func (s *Service) handleCloudConnect(c *gin.Context) {
	var req cloudConnectReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Provider == "" {
		req.Provider = "aws"
	}
	if req.Provider != "aws" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only provider 'aws' is supported in this iteration"})
		return
	}
	if strings.TrimSpace(req.RoleARN) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_arn is required"})
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "secret_id (vault broker credential) is required"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
		return
	}

	region := req.Region
	if region == "" {
		region = "us-east-1"
	}
	ttl := cloudJITDefaultTTL
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}
	if ttl > cloudJITMaxTTL {
		ttl = cloudJITMaxTTL
	}
	if ttl < cloudJITMinTTL {
		ttl = cloudJITMinTTL
	}

	// Pull the broker credentials server-side. They never leave the service.
	bctx := orgctx.WithBypassRLS(ctx)
	rawSecret, err := s.vaultSvc.Use(bctx, req.SecretID)
	if err != nil {
		s.logger.Warn("handleCloudConnect: broker credential unavailable",
			zap.String("secret_id", req.SecretID), zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "broker credential unavailable"})
		return
	}
	var broker struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	jsonErr := json.Unmarshal(rawSecret, &broker)
	for i := range rawSecret {
		rawSecret[i] = 0 // wipe plaintext promptly
	}
	if jsonErr != nil || broker.AccessKeyID == "" || broker.SecretAccessKey == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "broker secret must be JSON with access_key_id and secret_access_key"})
		return
	}

	// AssumeRole for the caller. SessionName ties the STS session to the
	// OpenIDX user for CloudTrail correlation.
	sessionName := cloudSessionName(userID)
	stsClient := newAssumeRoleClient(region, broker.AccessKeyID, broker.SecretAccessKey)
	broker.SecretAccessKey = "" // wipe
	out, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(req.RoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(int32(ttl.Seconds())),
	})
	if err != nil {
		s.logger.Warn("handleCloudConnect: AssumeRole failed",
			zap.String("role_arn", req.RoleARN), zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "AssumeRole failed: " + err.Error()})
		return
	}
	if out.Credentials == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "STS returned no credentials"})
		return
	}
	cred := out.Credentials
	expiresAt := time.Now().Add(ttl)
	if cred.Expiration != nil {
		expiresAt = *cred.Expiration
	}

	// Record the brokered session (auto-expires; nothing to revoke).
	var sessionID string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO brokered_sessions (org_id, user_id, target_type, target, principal, reason, status, expires_at)
		VALUES ($1,$2,'cloud',$3,$4,NULLIF($5,''),'active',$6)
		RETURNING id`,
		org.ID, userID, req.RoleARN, sessionName, req.Reason, expiresAt).Scan(&sessionID); err != nil {
		s.logger.Error("handleCloudConnect: session record failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record session"})
		return
	}
	s.logAuditEvent(c, "pam.cloud_jit_issued", sessionID, "brokered_session", map[string]interface{}{
		"provider": "aws", "role_arn": req.RoleARN, "region": region,
		"user_id": userID, "ttl_minutes": int(ttl.Minutes()), "console": req.Console,
	})

	resp := gin.H{
		"session_id":        sessionID,
		"provider":          "aws",
		"role_arn":          req.RoleARN,
		"region":            region,
		"access_key_id":     aws.ToString(cred.AccessKeyId),
		"secret_access_key": aws.ToString(cred.SecretAccessKey),
		"session_token":     aws.ToString(cred.SessionToken),
		"expires_at":        expiresAt,
	}

	// Optional federated console URL.
	if req.Console {
		signinURL, cerr := buildAWSConsoleURL(ctx,
			aws.ToString(cred.AccessKeyId),
			aws.ToString(cred.SecretAccessKey),
			aws.ToString(cred.SessionToken),
			int(ttl.Seconds()))
		if cerr != nil {
			s.logger.Warn("handleCloudConnect: console URL build failed", zap.Error(cerr))
			resp["console_error"] = "failed to build console URL"
		} else {
			resp["console_url"] = signinURL
		}
	}
	// Wipe the secret values out of local vars (the response already copied them).
	cred.SecretAccessKey = aws.String("")

	c.JSON(http.StatusOK, resp)
}

// cloudSessionName builds an STS RoleSessionName from the user id. STS requires
// [\w+=,.@-]{2,64}; UUIDs already satisfy this, prefixed for readability.
func cloudSessionName(userID string) string {
	name := "openidx-" + userID
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// buildAWSConsoleURL exchanges temporary credentials for a federated console
// sign-in URL using the AWS federation endpoint. The operator can open this to
// land in a time-boxed console session without any static console password.
func buildAWSConsoleURL(ctx context.Context, accessKeyID, secretAccessKey, sessionToken string, ttlSeconds int) (string, error) {
	sessionJSON, err := json.Marshal(map[string]string{
		"sessionId":    accessKeyID,
		"sessionKey":   secretAccessKey,
		"sessionToken": sessionToken,
	})
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	// 1. Get a sign-in token.
	q := url.Values{}
	q.Set("Action", "getSigninToken")
	q.Set("SessionDuration", fmt.Sprintf("%d", clampConsoleDuration(ttlSeconds)))
	q.Set("Session", string(sessionJSON))
	reqURL := awsFederationEndpoint + "?" + q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	res, err := cloudJITHTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("getSigninToken request: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("getSigninToken status %d", res.StatusCode)
	}
	var tok struct {
		SigninToken string `json:"SigninToken"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.SigninToken == "" {
		return "", fmt.Errorf("decode signin token")
	}

	// 2. Build the login URL.
	lq := url.Values{}
	lq.Set("Action", "login")
	lq.Set("Issuer", "openidx")
	lq.Set("Destination", awsConsoleDestination)
	lq.Set("SigninToken", tok.SigninToken)
	return awsFederationEndpoint + "?" + lq.Encode(), nil
}

// clampConsoleDuration keeps the console SessionDuration within AWS's accepted
// range (900s..43200s) independent of the credential TTL.
func clampConsoleDuration(sec int) int {
	if sec < 900 {
		return 900
	}
	if sec > 43200 {
		return 43200
	}
	return sec
}
