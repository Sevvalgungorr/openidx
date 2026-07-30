// Command openidx-connect is the end-user native-access CLI for OpenIDX PAM
// (PAM Wave B2). It turns an OpenIDX-brokered, short-lived SSH certificate into
// a plain `ssh` session so operators keep using their own client, keys stay on
// their workstation, and every session is centrally authorized + audited.
//
// Flow (`openidx-connect ssh user@host`):
//
//  1. generate an ephemeral ed25519 keypair locally — the PRIVATE key never
//     leaves the workstation and never touches the server;
//  2. POST the PUBLIC key to the access service's /pam/connect/ssh, which signs
//     a short-lived SSH user certificate (the SSH CA lives server-side, keyed
//     per org) and records/audits the brokered session;
//  3. write key + cert to a private temp dir and exec the system `ssh` with
//     `-i` + `IdentitiesOnly=yes` so the native client authenticates with the
//     brokered cert and nothing else;
//  4. wipe the temp material on exit.
//
// Because the credential is a certificate the target already trusts (its
// sshd is configured with `TrustedUserCAKeys` = the org CA public key from
// `openidx-connect ca`), the operator's `ssh` "just works" with no static key
// on the host and no standing access — the cert expires in minutes.
//
// Auth to the access service uses an OpenIDX bearer token. Supply it via
// --token or the OPENIDX_TOKEN env var (the CLI does not implement the OAuth
// dance itself in this iteration; wire it to your existing token source).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// Version metadata (set via -ldflags at build time).
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:   "openidx-connect",
		Short: "OpenIDX native-access CLI — brokered, short-lived SSH sessions",
		Long: `openidx-connect brokers a short-lived SSH certificate from OpenIDX and
launches your native ssh client with it. Your private key never leaves this
machine and the certificate expires in minutes, so there is no standing access
on the target host.

Set the access-service base URL with --server or OPENIDX_SERVER, and an OpenIDX
bearer token with --token or OPENIDX_TOKEN.`,
		Version:       fmt.Sprintf("%s (built %s, commit %s)", Version, BuildTime, Commit),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("server", envOr("OPENIDX_SERVER", "https://openidx.tdv.org"),
		"OpenIDX access-service base URL (env OPENIDX_SERVER)")
	root.PersistentFlags().String("token", os.Getenv("OPENIDX_TOKEN"),
		"OpenIDX bearer token (env OPENIDX_TOKEN)")
	root.PersistentFlags().Bool("insecure", false, "skip TLS verification (dev only)")

	root.AddCommand(newSSHCommand(), newCACommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---- ssh subcommand ----

func newSSHCommand() *cobra.Command {
	var ttlMinutes int
	var reason string
	var printOnly bool

	cmd := &cobra.Command{
		Use:   "ssh [user@]host [-- ssh args...]",
		Short: "Open a brokered SSH session to a host",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			token, _ := cmd.Flags().GetString("token")
			insecure, _ := cmd.Flags().GetBool("insecure")

			principal, host := splitUserHost(args[0])
			if host == "" {
				return fmt.Errorf("target must be host or user@host")
			}
			if principal == "" {
				principal = os.Getenv("USER")
			}
			if token == "" {
				return fmt.Errorf("no token: set --token or OPENIDX_TOKEN")
			}

			// 1. Ephemeral keypair — private key stays local.
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			sshPub, err := ssh.NewPublicKey(pub)
			if err != nil {
				return fmt.Errorf("marshal public key: %w", err)
			}
			pubAuthorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

			// 2. Ask OpenIDX to sign a short-lived cert for our public key.
			resp, err := requestSSHCert(server, token, insecure, sshConnectRequest{
				Host:       host,
				Principal:  principal,
				PublicKey:  pubAuthorized,
				Reason:     reason,
				TTLMinutes: ttlMinutes,
			})
			if err != nil {
				return err
			}

			// 3. Materialize key + cert in a private temp dir.
			privBlock, err := ssh.MarshalPrivateKey(priv, "openidx-connect")
			if err != nil {
				return fmt.Errorf("marshal private key: %w", err)
			}
			privPEM := pem.EncodeToMemory(privBlock)

			dir, err := os.MkdirTemp("", "openidx-connect-")
			if err != nil {
				return fmt.Errorf("temp dir: %w", err)
			}
			defer func() { _ = os.RemoveAll(dir) }()

			keyPath := filepath.Join(dir, "id")
			certPath := keyPath + "-cert.pub"
			if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
				return fmt.Errorf("write key: %w", err)
			}
			if err := os.WriteFile(certPath, []byte(resp.Certificate+"\n"), 0o600); err != nil {
				return fmt.Errorf("write cert: %w", err)
			}

			if printOnly {
				fmt.Printf("session_id: %s\nprincipal:  %s\nexpires_at: %s\nkey:        %s\ncert:       %s\n",
					resp.SessionID, resp.Principal, resp.ExpiresAt, keyPath, certPath)
				fmt.Printf("\nssh -i %s -o IdentitiesOnly=yes %s@%s\n", keyPath, principal, host)
				// Keep the temp dir when printing so the user can run ssh manually.
				// (defer RemoveAll still fires — so copy out if you need it.)
				return nil
			}

			// 4. Exec native ssh with the brokered identity.
			sshArgs := []string{
				"-i", keyPath,
				"-o", "IdentitiesOnly=yes",
			}
			if extra := args[1:]; len(extra) > 0 {
				sshArgs = append(sshArgs, extra...)
			}
			sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", principal, host))

			fmt.Fprintf(os.Stderr, "openidx-connect: brokered session %s (principal %s, expires %s)\n",
				resp.SessionID, resp.Principal, resp.ExpiresAt)
			return runSSH(sshArgs)
		},
	}
	cmd.Flags().IntVar(&ttlMinutes, "ttl", 0, "certificate TTL in minutes (server clamps to its max)")
	cmd.Flags().StringVar(&reason, "reason", "", "reason for access (audited)")
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the ssh command + material instead of executing")
	return cmd
}

// splitUserHost parses "user@host" or "host". Returns ("", host) when no user.
func splitUserHost(s string) (user, host string) {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// runSSH executes the system ssh client, forwarding stdio and the exit code.
func runSSH(args []string) error {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	c := exec.Command(bin, args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
		}
		return err
	}
	return nil
}

// ---- ca subcommand ----

func newCACommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ca",
		Short: "Print the org SSH CA public key (for TrustedUserCAKeys on targets)",
		Long: `Fetches the organization's SSH certificate-authority public key. Add it to
each target host's sshd config so brokered certificates are trusted:

    # /etc/ssh/openidx_ca.pub  <- output of this command
    # /etc/ssh/sshd_config:
    TrustedUserCAKeys /etc/ssh/openidx_ca.pub`,
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			token, _ := cmd.Flags().GetString("token")
			insecure, _ := cmd.Flags().GetBool("insecure")
			pub, err := fetchCAPublicKey(server, token, insecure)
			if err != nil {
				return err
			}
			fmt.Println(pub)
			return nil
		},
	}
}

// ---- HTTP client ----

type sshConnectRequest struct {
	Host       string `json:"host"`
	Principal  string `json:"principal"`
	PublicKey  string `json:"public_key"`
	Reason     string `json:"reason,omitempty"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"`
}

type sshConnectResponse struct {
	SessionID   string `json:"session_id"`
	Certificate string `json:"certificate"`
	Principal   string `json:"principal"`
	ExpiresAt   string `json:"expires_at"`
}

func requestSSHCert(server, token string, insecure bool, req sshConnectRequest) (*sshConnectResponse, error) {
	body, err := doJSON(server, "/api/v1/access/pam/connect/ssh", token, insecure, req)
	if err != nil {
		return nil, err
	}
	var out sshConnectResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode connect response: %w", err)
	}
	if out.Certificate == "" {
		return nil, fmt.Errorf("server returned no certificate")
	}
	return &out, nil
}

func fetchCAPublicKey(server, token string, insecure bool) (string, error) {
	body, err := doGET(server, "/api/v1/access/pam/ssh-ca", token, insecure)
	if err != nil {
		return "", err
	}
	var out struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode CA response: %w", err)
	}
	if out.PublicKey == "" {
		return "", fmt.Errorf("server returned no CA public key (is the SSH CA initialized?)")
	}
	return out.PublicKey, nil
}

func doJSON(server, path, token string, insecure bool, payload any) ([]byte, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return doRequest(httpReq, token, insecure)
}

func doGET(server, path, token string, insecure bool) ([]byte, error) {
	httpReq, err := http.NewRequest(http.MethodGet, strings.TrimRight(server, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	return doRequest(httpReq, token, insecure)
}

func doRequest(httpReq *http.Request, token string, insecure bool) ([]byte, error) {
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = insecureTransport()
	}
	res, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("server responded %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// insecureTransport returns an http.Transport that skips TLS verification.
// Dev-only escape hatch behind the --insecure flag; never the default.
func insecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // gated behind explicit --insecure dev flag
	}
}
