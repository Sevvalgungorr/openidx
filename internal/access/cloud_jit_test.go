package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// fakeSTS returns canned AssumeRole output and captures the input.
type fakeSTS struct {
	lastInput *sts.AssumeRoleInput
	err       error
}

func (f *fakeSTS) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	exp := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &stypes.Credentials{
			AccessKeyId:     aws.String("ASIAFAKE"),
			SecretAccessKey: aws.String("secretfake"),
			SessionToken:    aws.String("tokenfake"),
			Expiration:      &exp,
		},
	}, nil
}

func TestClampConsoleDuration(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 900}, {900, 900}, {3600, 3600}, {43200, 43200}, {99999, 43200}, {100, 900},
	}
	for _, c := range cases {
		if got := clampConsoleDuration(c.in); got != c.want {
			t.Errorf("clampConsoleDuration(%d)=%d, want %d", c.in, got, c.want)
		}
	}
}

func TestCloudSessionName(t *testing.T) {
	if n := cloudSessionName("abc"); n != "openidx-abc" {
		t.Errorf("got %q", n)
	}
	long := cloudSessionName(strings.Repeat("x", 100))
	if len(long) > 64 {
		t.Errorf("session name not clamped to 64: %d", len(long))
	}
}

// TestBuildAWSConsoleURL drives the federation exchange against a mock endpoint.
func TestBuildAWSConsoleURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "getSigninToken" {
			t.Errorf("unexpected action %s", r.URL.Query().Get("Action"))
		}
		if r.URL.Query().Get("Session") == "" {
			t.Error("missing Session param")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"SigninToken": "STOK123"})
	}))
	defer srv.Close()

	oldEP := awsFederationEndpoint
	awsFederationEndpoint = srv.URL
	defer func() { awsFederationEndpoint = oldEP }()

	u, err := buildAWSConsoleURL(context.Background(), "AK", "SK", "TOK", 3600)
	if err != nil {
		t.Fatalf("buildAWSConsoleURL: %v", err)
	}
	if !strings.Contains(u, "Action=login") || !strings.Contains(u, "SigninToken=STOK123") {
		t.Fatalf("unexpected console url: %s", u)
	}
}

// TestFakeSTSAssumeRoleShape sanity-checks the fake produces usable creds and
// records the input the handler will send (role ARN + session name + duration).
func TestFakeSTSAssumeRoleShape(t *testing.T) {
	f := &fakeSTS{}
	out, err := f.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::111:role/admin"),
		RoleSessionName: aws.String("openidx-u1"),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(out.Credentials.AccessKeyId) != "ASIAFAKE" {
		t.Fatal("bad creds")
	}
	if aws.ToString(f.lastInput.RoleArn) != "arn:aws:iam::111:role/admin" {
		t.Fatal("role arn not captured")
	}
}
