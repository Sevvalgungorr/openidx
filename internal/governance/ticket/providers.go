package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpDoer is the subset of *http.Client used, so tests can inject a fake.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// ---- ServiceNow ----

// ServiceNowValidator verifies records via the ServiceNow Table API
// (/api/now/table/<table>?sysparm_query=number=<ref>). Basic-auth in this cut;
// OAuth is a config swap on the injected client.
type ServiceNowValidator struct {
	BaseURL  string // e.g. https://acme.service-now.com
	Table    string // e.g. change_request (default)
	Username string
	Password string
	Client   httpDoer
	// StateField / AssigneeField let deployments map their instance's fields.
	StateField    string // default "state"
	AssigneeField string // default "assigned_to"
}

func (s ServiceNowValidator) Provider() string { return "servicenow" }

func (s ServiceNowValidator) Validate(ctx context.Context, ref, requesterHint string) (*Result, error) {
	table := s.Table
	if table == "" {
		table = "change_request"
	}
	stateField := s.StateField
	if stateField == "" {
		stateField = "state"
	}
	assigneeField := s.AssigneeField
	if assigneeField == "" {
		assigneeField = "assigned_to"
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	q := url.Values{}
	q.Set("sysparm_query", "number="+ref)
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_display_value", "true")
	endpoint := strings.TrimRight(s.BaseURL, "/") + "/api/now/table/" + table + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.Username, s.Password)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("servicenow status %d", res.StatusCode)
	}

	var payload struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode servicenow response: %w", err)
	}
	if len(payload.Result) == 0 {
		return &Result{Valid: false, Ref: ref, Provider: "servicenow", Reason: "ticket not found"}, nil
	}
	rec := payload.Result[0]
	return &Result{
		Valid:      true,
		Ref:        ref,
		State:      snowString(rec[stateField]),
		Summary:    snowString(rec["short_description"]),
		AssignedTo: snowString(rec[assigneeField]),
		Provider:   "servicenow",
	}, nil
}

// snowString coerces a ServiceNow field (string, or {display_value,value}) to a
// plain string.
func snowString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if dv, ok := t["display_value"].(string); ok {
			return dv
		}
		if val, ok := t["value"].(string); ok {
			return val
		}
	}
	return ""
}

// ---- Jira ----

// JiraValidator verifies issues via the Jira REST API
// (/rest/api/2/issue/<key>). Basic-auth with an API token in this cut.
type JiraValidator struct {
	BaseURL  string // e.g. https://acme.atlassian.net
	Email    string // account email (basic-auth username)
	APIToken string // Atlassian API token (basic-auth password)
	Client   httpDoer
}

func (j JiraValidator) Provider() string { return "jira" }

func (j JiraValidator) Validate(ctx context.Context, ref, requesterHint string) (*Result, error) {
	client := j.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	endpoint := strings.TrimRight(j.BaseURL, "/") + "/rest/api/2/issue/" + url.PathEscape(ref) +
		"?fields=status,summary,assignee"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(j.Email, j.APIToken)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode == http.StatusNotFound {
		return &Result{Valid: false, Ref: ref, Provider: "jira", Reason: "issue not found"}, nil
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("jira status %d", res.StatusCode)
	}

	var payload struct {
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee struct {
				EmailAddress string `json:"emailAddress"`
				DisplayName  string `json:"displayName"`
			} `json:"assignee"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode jira response: %w", err)
	}
	assignee := payload.Fields.Assignee.EmailAddress
	if assignee == "" {
		assignee = payload.Fields.Assignee.DisplayName
	}
	return &Result{
		Valid:      true,
		Ref:        ref,
		State:      payload.Fields.Status.Name,
		Summary:    payload.Fields.Summary,
		AssignedTo: assignee,
		Provider:   "jira",
	}, nil
}
