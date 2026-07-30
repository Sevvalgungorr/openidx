package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeRef(t *testing.T) {
	cases := []struct {
		provider, in, want string
		wantErr            bool
	}{
		{"servicenow", " chg0031234 ", "CHG0031234", false},
		{"servicenow", "INC0012345", "INC0012345", false},
		{"servicenow", "not-a-ref", "", true},
		{"jira", "ops-1234", "OPS-1234", false},
		{"jira", "OPS1234", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeRef(c.provider, c.in)
		if c.wantErr && err == nil {
			t.Errorf("NormalizeRef(%q,%q) expected error", c.provider, c.in)
		}
		if !c.wantErr && got != c.want {
			t.Errorf("NormalizeRef(%q,%q)=%q, want %q", c.provider, c.in, got, c.want)
		}
	}
}

func TestEnforce_NotRequired(t *testing.T) {
	res, err := Enforce(context.Background(), NullValidator{}, EnforcementPolicy{Required: false}, "", "")
	if err != nil || !res.Valid {
		t.Fatalf("not-required should pass: res=%+v err=%v", res, err)
	}
}

func TestEnforce_RequiredButMissing(t *testing.T) {
	_, err := Enforce(context.Background(), NullValidator{ProviderID: "jira"}, EnforcementPolicy{Required: true}, "", "")
	if err == nil {
		t.Fatal("expected error when ticket required but missing")
	}
}

func TestServiceNowValidator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sysparm_query") != "number=CHG0031234" {
			t.Errorf("bad query: %s", r.URL.RawQuery)
		}
		u, p, _ := r.BasicAuth()
		if u != "svc" || p != "pw" {
			t.Errorf("bad basic auth: %s/%s", u, p)
		}
		w.Write([]byte(`{"result":[{"state":{"display_value":"Implement"},"short_description":"DB maintenance","assigned_to":{"display_value":"alice"}}]}`))
	}))
	defer srv.Close()

	v := ServiceNowValidator{BaseURL: srv.URL, Username: "svc", Password: "pw", Client: srv.Client()}
	policy := EnforcementPolicy{Required: true, AcceptStates: []string{"Implement", "Approved"}}
	res, err := Enforce(context.Background(), v, policy, "CHG0031234", "alice")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !res.Valid || res.State != "Implement" || res.AssignedTo != "alice" {
		t.Fatalf("unexpected result: %+v", res)
	}

	// State not in accepted list → rejected.
	policy2 := EnforcementPolicy{Required: true, AcceptStates: []string{"Closed"}}
	if _, err := Enforce(context.Background(), v, policy2, "CHG0031234", "alice"); err == nil {
		t.Fatal("expected rejection for unaccepted state")
	}

	// Owner mismatch → rejected.
	policy3 := EnforcementPolicy{Required: true, MustMatchOwner: true}
	if _, err := Enforce(context.Background(), v, policy3, "CHG0031234", "bob"); err == nil {
		t.Fatal("expected rejection for owner mismatch")
	}
}

func TestServiceNowValidator_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()
	v := ServiceNowValidator{BaseURL: srv.URL, Client: srv.Client()}
	res, err := v.Validate(context.Background(), "CHG0000001", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("expected not-found to be invalid")
	}
}

func TestJiraValidator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/issue/OPS-1234" {
			t.Errorf("bad path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"fields":{"summary":"Prod access","status":{"name":"In Progress"},"assignee":{"emailAddress":"alice@acme.com"}}}`))
	}))
	defer srv.Close()

	v := JiraValidator{BaseURL: srv.URL, Email: "e", APIToken: "t", Client: srv.Client()}
	policy := EnforcementPolicy{Required: true, AcceptStates: []string{"In Progress"}}
	res, err := Enforce(context.Background(), v, policy, "OPS-1234", "alice@acme.com")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !res.Valid || res.State != "In Progress" || res.AssignedTo != "alice@acme.com" {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestJiraValidator_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	v := JiraValidator{BaseURL: srv.URL, Client: srv.Client()}
	res, err := v.Validate(context.Background(), "OPS-9999", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("expected not-found invalid")
	}
}
