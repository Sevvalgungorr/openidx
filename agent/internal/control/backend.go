package control

import (
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/enrollment"
	"github.com/openidx/openidx/agent/internal/sso"
)

// realBackend is the production backend: it calls the existing sso / enrollment
// / desktoppam packages verbatim. Tests substitute a fake implementing the same
// `backend` interface.
type realBackend struct{}

func (realBackend) Login(ctx context.Context, serverURL string) (*sso.Tokens, error) {
	return sso.Login(ctx, serverURL)
}

func (realBackend) Enroll(logger *zap.Logger, serverURL, token, configDir string) (agentID, deviceID, zitiIdentity string, err error) {
	res, err := enrollment.Enroll(logger, serverURL, token, configDir)
	if err != nil {
		return "", "", "", err
	}
	return res.AgentConfig.AgentID, res.AgentConfig.DeviceID, res.ZitiIdentity, nil
}

func (realBackend) PamList(ctx context.Context, serverURL, token string) ([]desktoppam.Entry, error) {
	return desktoppam.ListEntries(ctx, serverURL, token)
}

func (realBackend) PamConnect(ctx context.Context, serverURL, token, entryID string) (string, error) {
	res, err := desktoppam.Connect(ctx, serverURL, token, entryID)
	if err != nil {
		return "", err
	}
	url := res.ConnectURL
	if url == "" {
		url = res.URL
	}
	return url, nil
}

func (realBackend) PamRequest(ctx context.Context, serverURL, token, entryID, reason string) error {
	return desktoppam.RequestAccess(ctx, serverURL, token, entryID, reason)
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
