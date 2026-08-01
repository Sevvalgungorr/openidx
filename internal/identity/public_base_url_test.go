package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Password reset, email verification and invitation links were hardcoded to
// http://localhost:3000 or http://localhost:<this service's port>. The second
// is wrong even in development — it addresses the API listener, not the browser
// app, so the recipient lands on a JSON 404. Both make the three flows unusable
// in any real deployment, which is why PUBLIC_BASE_URL now exists.

func TestPublicBaseURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "uses the configured public base URL",
			cfg:  &config.Config{PublicBaseURL: "https://id.example.com"},
			want: "https://id.example.com",
		},
		{
			name: "trims a trailing slash so callers can append a rooted path",
			cfg:  &config.Config{PublicBaseURL: "https://id.example.com/"},
			want: "https://id.example.com",
		},
		{
			name: "does not fall back to the API port",
			cfg:  &config.Config{Port: 8001},
			want: "http://localhost:3000",
		},
		{
			name: "tolerates a nil config",
			cfg:  nil,
			want: "http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{cfg: tt.cfg}
			if got := s.publicBaseURL(); got != tt.want {
				t.Errorf("publicBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// recordingEmailer captures the baseURL each send was given.
type recordingEmailer struct{ resetBaseURL string }

func (r *recordingEmailer) SendVerificationEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return nil
}

func (r *recordingEmailer) SendInvitationEmail(ctx context.Context, to, inviterName, token, baseURL string) error {
	return nil
}

func (r *recordingEmailer) SendPasswordResetEmail(ctx context.Context, to, userName, token, baseURL string) error {
	r.resetBaseURL = baseURL
	return nil
}

func (r *recordingEmailer) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	return nil
}

func (r *recordingEmailer) SendAsync(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	return nil
}

// TestForgotPasswordUsesPublicBaseURL is the end-to-end half: the configured
// origin has to survive all the way into the mail, not merely be readable.
func TestForgotPasswordUsesPublicBaseURL(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, authTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	seedAuthUser(t, db, ctx, authOrgA, "linkuser", "link@example.com", authGoodPassword)

	mailer := &recordingEmailer{}
	s := NewService(db, nil, &config.Config{PublicBaseURL: "https://id.example.com/"}, zap.NewNop())
	s.emailService = mailer

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/forgot-password",
		strings.NewReader(`{"email":"link@example.com"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: authOrgA}))

	s.handleForgotPassword(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if mailer.resetBaseURL != "https://id.example.com" {
		t.Errorf("reset email baseURL = %q, want %q (was hardcoded to localhost:3000)",
			mailer.resetBaseURL, "https://id.example.com")
	}
	if strings.Contains(mailer.resetBaseURL, "localhost") {
		t.Errorf("reset link still points at localhost: %q", mailer.resetBaseURL)
	}
}
