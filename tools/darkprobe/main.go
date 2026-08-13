// Command darkprobe proves that an application with no inbound firewall port
// is still reachable over the Ziti overlay by an authorised identity, and is
// not reachable by an unauthorised one.
//
// It dials a service purely through the overlay using the caller's enrolled
// identity file. There is no listening port on the application host other than
// loopback, so a successful response can only have arrived over the overlay.
//
// Usage: darkprobe <identity.json> <service-name> [http-path]
//
// If the service terminates TLS (e.g. an HTTPS app on 443), set DARKPROBE_TLS=1.
// The overlay already provides mutual authentication and end-to-end encryption,
// so certificate verification is skipped here: the target presents a
// certificate for its public name while we dial it by service name, and this
// tool exists to prove reachability and authorisation, not chain validity.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/openziti/sdk-golang/ziti"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: darkprobe <identity.json> <service> [path]")
		os.Exit(2)
	}
	idFile, service := os.Args[1], os.Args[2]
	path := "/"
	if len(os.Args) > 3 {
		path = os.Args[3]
	}

	cfg, err := ziti.NewConfigFromFile(idFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity:", err)
		os.Exit(1)
	}
	ctx, err := ziti.NewContext(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "context:", err)
		os.Exit(1)
	}
	defer ctx.Close()

	// Every connection goes through the overlay. A plain TCP dial to the target
	// would fail (the app binds loopback only), so anything that succeeds here
	// is proof the overlay carried it.
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return ctx.Dial(service)
	}
	transport := &http.Transport{DialContext: dial}
	scheme := "http://"
	if os.Getenv("DARKPROBE_TLS") == "1" {
		scheme = "https://"
		// The target is dialled by Ziti service name, but it selects its
		// certificate by SNI. Sending the service name as SNI makes a
		// virtual-hosted origin fail the handshake outright, so allow the real
		// hostname to be supplied. This mirrors what a tunneller does: it
		// intercepts the app's own DNS name, so SNI is the app name there too.
		sni := os.Getenv("DARKPROBE_SNI")
		transport.DialTLSContext = func(c context.Context, n, a string) (net.Conn, error) {
			raw, err := dial(c, n, a)
			if err != nil {
				return nil, err
			}
			//nolint:gosec // see the note above: the overlay is the trust boundary here.
			return tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: sni}), nil
		}
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport}

	// The Host header defaults to the service name. A virtual-hosted origin
	// (or a reverse proxy routing by host) will answer 404 for that, which
	// looks like a broken service but is really a wrong Host. Let the caller
	// send the app's real name; the overlay hop is unaffected either way.
	req, err := http.NewRequest(http.MethodGet, scheme+service+path, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(1)
	}
	if host := os.Getenv("DARKPROBE_HOST"); host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DENIED or unreachable:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("status=%d body=%s\n", resp.StatusCode, string(body))
}
