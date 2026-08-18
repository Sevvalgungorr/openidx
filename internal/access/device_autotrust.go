package access

import (
	"strings"

	"github.com/openidx/openidx/internal/common/config"
	"go.uber.org/zap"
)

// autotrustMode returns the normalized DEVICE_AUTOTRUST_MODE (off|observe|enforce).
func autotrustMode(cfg *config.Config) string {
	if cfg == nil {
		return "off"
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DeviceAutotrustMode)) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// orgAutotrustAllowed reports whether org is eligible for auto-trust given the
// optional DEVICE_AUTOTRUST_KNOWN_ORGS allow-list. An empty list means "any
// org" — the operator opted in globally by setting enforce.
func orgAutotrustAllowed(cfg *config.Config, orgID string) bool {
	if cfg == nil {
		return false
	}
	list := strings.TrimSpace(cfg.DeviceAutotrustKnownOrgs)
	if list == "" {
		return true
	}
	for _, o := range strings.Split(list, ",") {
		if strings.TrimSpace(o) == orgID {
			return true
		}
	}
	return false
}

// decideAutoTrust returns whether a device enrolled via an enrollment session
// should be auto-marked trusted (and the effective mode, for logging). Trust is
// granted ONLY in "enforce" mode when the enrolling session was MFA-verified
// server-side, the org is allow-listed, and — if posture is required — a
// compliant baseline is available (postureOK). At enroll time no posture report
// exists yet, so callers pass postureOK=false when RequirePosture is set, which
// safely defers trust to a later report or admin approval.
//
// The mfaVerified input MUST come from the server-verified enrollment_sessions
// row (the console session that created the code), never from agent-supplied
// request data.
func decideAutoTrust(cfg *config.Config, logger *zap.Logger, mfaVerified, postureOK bool, orgID string) (trusted bool, mode string) {
	mode = autotrustMode(cfg)
	if mode == "off" {
		return false, mode
	}

	eligible := mfaVerified && orgAutotrustAllowed(cfg, orgID)
	if cfg.DeviceAutotrustRequirePosture {
		eligible = eligible && postureOK
	}
	if !eligible {
		return false, mode
	}

	if mode == "observe" {
		if logger != nil {
			logger.Info("device auto-trust (observe): WOULD auto-trust device",
				zap.String("org_id", orgID), zap.Bool("mfa_verified", mfaVerified))
		}
		return false, mode
	}
	return true, mode // enforce
}
