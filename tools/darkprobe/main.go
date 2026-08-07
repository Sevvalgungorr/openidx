// Command darkprobe proves that an application with no inbound firewall port
// is still reachable over the Ziti overlay by an authorised identity, and is
// not reachable by an unauthorised one.
//
// It dials a service purely through the overlay using the caller's enrolled
// identity file. There is no listening port on the application host other than
// loopback, so a successful response can only have arrived over the overlay.
//
// Usage: darkprobe <identity.json> <service-name> [http-path]
package main

import (
	"context"
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
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return ctx.Dial(service)
			},
		},
	}

	resp, err := client.Get("http://" + service + path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DENIED or unreachable:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("status=%d body=%s\n", resp.StatusCode, string(body))
}
