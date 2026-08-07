// Command lbrender renders an upstream pool into the APISIX upstream object
// using the same code path the reconciler uses, so an operator can see exactly
// what a pool will produce before it goes live, and so the live edge can be
// driven from the database during verification.
//
// Read-only against the database; prints JSON on stdout.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/common/database"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lbrender <pool-id> [scheme] [pass_host] [upstream_host]")
		os.Exit(1)
	}
	scheme := "http"
	if len(os.Args) > 2 {
		scheme = os.Args[2]
	}
	passHost, upstreamHost := "", ""
	if len(os.Args) > 3 {
		passHost = os.Args[3]
	}
	if len(os.Args) > 4 {
		upstreamHost = os.Args[4]
	}

	db, err := database.NewPostgres(os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer db.Close()

	pool, err := access.LoadPoolForRender(context.Background(), db, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load pool:", err)
		os.Exit(1)
	}
	up, err := pool.BuildUpstream(scheme, passHost, upstreamHost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		os.Exit(1)
	}
	b, err := json.Marshal(up)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
