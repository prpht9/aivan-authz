//go:build devtools

// Phase E's console mint. It lives behind the devtools build tag so the image
// (which builds without the tag) cannot contain it, and so Phase F can delete
// two files rather than unpick the command from main.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chris/aivan-authz/internal/config"
	"github.com/chris/aivan-authz/internal/console"
)

// devSessionUsage is printed for a missing or extra flag, so the command is
// self-describing in a pod with no man page.
const devSessionUsage = `usage: authz dev-session --username <name> [--origin <host>] [--kind browser|phone|tablet]
                        [--alg ed25519|es256] [--name <label>]

Mints a session cookie for a throwaway device, for testing the proxy loop
before enrollment exists. Requires AIVAN_HOSTS and AIVAN_DB_URL.`

func init() {
	extraCommands["dev-session"] = devSession
	extraUsage = append(extraUsage,
		"  dev-session --username <name>   testing only: mint a session cookie (devtools build)")
}

func devSession(out io.Writer, args []string) error {
	opts, err := parseDevSession(args)
	if err != nil {
		return err
	}

	// The origin is a host the gate serves, so a typo is refused here rather
	// than producing a device whose every request is an origin mismatch.
	hosts, err := config.ParseHosts(os.Getenv("AIVAN_HOSTS"))
	if err != nil {
		return err
	}
	if opts.Origin == "" {
		if len(hosts) != 1 {
			return fmt.Errorf("--origin is required when AIVAN_HOSTS lists %d hosts", len(hosts))
		}
		opts.Origin = hosts[0]
	} else if !contains(hosts, opts.Origin) {
		return fmt.Errorf("--origin %q is not in AIVAN_HOSTS (%v)", opts.Origin, hosts)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := console.MintDevSession(ctx, db.Pool, opts)
	if err != nil {
		return err
	}
	return console.WriteDevSession(out, res)
}

func parseDevSession(args []string) (console.DevSessionOptions, error) {
	var o console.DevSessionOptions
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			return o, errors.New(devSessionUsage)
		}
		v := args[i+1]
		switch args[i] {
		case "--username":
			o.Username = v
		case "--origin":
			o.Origin = v
		case "--kind":
			o.Kind = v
		case "--alg":
			o.Alg = v
		case "--name":
			o.Name = v
		default:
			return o, fmt.Errorf("%s\nunknown flag %q", devSessionUsage, args[i])
		}
		i++
	}
	if o.Username == "" {
		return o, errors.New(devSessionUsage)
	}
	return o, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
