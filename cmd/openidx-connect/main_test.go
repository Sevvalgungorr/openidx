package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitUserHost(t *testing.T) {
	cases := []struct{ in, user, host string }{
		{"root@db01", "root", "db01"},
		{"db01", "", "db01"},
		{"admin@10.0.0.5", "admin", "10.0.0.5"},
		{"user@name@host", "user@name", "host"}, // last @ wins
	}
	for _, c := range cases {
		u, h := splitUserHost(c.in)
		if u != c.user || h != c.host {
			t.Errorf("splitUserHost(%q) = (%q,%q), want (%q,%q)", c.in, u, h, c.user, c.host)
		}
	}
}

func TestRequestSSHCert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access/pam/connect/ssh" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tkn" {
			t.Errorf("auth header = %q", got)
		}
		var req sshConnectRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Host != "db01" || req.Principal != "root" || req.PublicKey == "" {
			t.Errorf("bad request payload: %+v", req)
		}
		_ = json.NewEncoder(w).Encode(sshConnectResponse{
			SessionID:   "sess-1",
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA...",
			Principal:   "root",
			ExpiresAt:   "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	resp, err := requestSSHCert(srv.URL, "tkn", false, sshConnectRequest{
		Host: "db01", Principal: "root", PublicKey: "ssh-ed25519 AAAA test",
	})
	if err != nil {
		t.Fatalf("requestSSHCert: %v", err)
	}
	if resp.SessionID != "sess-1" || resp.Certificate == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRequestSSHCert_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access denied"}`))
	}))
	defer srv.Close()

	_, err := requestSSHCert(srv.URL, "tkn", false, sshConnectRequest{Host: "h", Principal: "p", PublicKey: "k"})
	if err == nil {
		t.Fatal("expected an error on 403")
	}
}

func TestFetchCAPublicKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access/pam/ssh-ca" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"public_key": "ssh-ed25519 AAAAC3Nz CA"})
	}))
	defer srv.Close()

	pub, err := fetchCAPublicKey(srv.URL, "tkn", false)
	if err != nil {
		t.Fatalf("fetchCAPublicKey: %v", err)
	}
	if pub != "ssh-ed25519 AAAAC3Nz CA" {
		t.Fatalf("pub = %q", pub)
	}
}
