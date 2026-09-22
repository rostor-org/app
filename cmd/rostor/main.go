// Command rostor is the Rostor core: `serve`, `migrate`, `bootstrap`, and an
// `admin` CLI that is strictly a client of the HTTP API (spec principle 6).
package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "migrate":
		err = runMigrate(ctx)
	case "bootstrap":
		err = runBootstrap(ctx, os.Args[2:])
	case "admin":
		err = runAdmin(ctx, os.Args[2:])
	case "version":
		fmt.Println("rostor 0.0.1-mvp")
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: rostor <command>

  serve        run the core (env: ROSTOR_DATABASE_URL, ROSTOR_DATA_DIR, ROSTOR_LISTEN, ROSTOR_TLS_HOSTS)
  migrate      apply database migrations
  bootstrap    create the tenant, CA, built-in roles and the first admin token
  admin ...    administer via the API (env: ROSTOR_URL, ROSTOR_TOKEN)`)
}
