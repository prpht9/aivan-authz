// Command authz-admin is the AIVan operator tool.
//
// It is built on a workstation and never copied into an image: the primary
// paths are hud actions, and this exists for when hud is down
// (doc/schema-handover.md §2 and §4).
//
// Subcommands:
//
//	enroll-new   mint a one-time enrollment code, printed once
//	list-devices list a person's devices
//	revoke       revoke a device and every session it holds
//	purge        remove expired nonces and sessions, also run as a CronJob
//	service      register, retire or list a service identity
//
// Every one of them reaches the database with the operator credential, which is
// the point: the gate's credential cannot run any of them, and neither can the
// gate's binary.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/config"
	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Every error a subcommand returns may quote what a database driver
		// said, and a driver's message can carry the connection string. The
		// scrub is the same one the gate's logger uses.
		fmt.Fprintln(os.Stderr, audit.Scrub(err.Error()))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing subcommand")
	}

	switch args[0] {
	case "enroll-new":
		return enrollNew(os.Stdout, args[1:])
	case "list-devices":
		return listDevices(os.Stdout, args[1:])
	case "revoke":
		return revoke(os.Stdout, args[1:])
	case "purge":
		return purge(os.Stdout, args[1:])
	case "service":
		return service(os.Stdout, args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: authz-admin <command>

commands:
  enroll-new --username <name> --origin <host> --kind <kind>
                                 mint a one-time enrollment code, printed once
  list-devices --username <name> list a person's devices
  revoke --device <uuid>         revoke a device and every session it holds
  purge                          remove expired nonces and sessions
  service register --name <name> --alg <alg> --key <path>
                                 add a service identity from its public key
  service retire --name <name>   stop accepting a service's signatures
  service list                   list registered services

This binary is not in the gate's image. It is a break-glass tool: the primary
paths are hud actions.`)
}

// consoleContext bounds every command: a database that does not answer should
// not hang an operator's shell.
func consoleContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func consolePool(ctx context.Context) (*store.DB, error) {
	dsn, err := config.DatabaseURL(os.Getenv)
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, dsn)
}

// listDevices prints one person's devices. A username with no devices is an
// empty table, not an error: the person may exist and never have enrolled.
func listDevices(out io.Writer, args []string) error {
	username, err := flagValue(args, "--username")
	if err != nil {
		return err
	}

	ctx, cancel := consoleContext()
	defer cancel()

	db, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	devices, err := console.ListDevices(ctx, db.Pool, username)
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	return console.WriteDevices(out, devices)
}

// enrollNew mints one pending enrollment and prints its code once. The origin
// is validated against AIVAN_HOSTS here, so the console and the gate agree on
// the set of hosts a record can name.
func enrollNew(out io.Writer, args []string) error {
	opts, err := parseFlags(args, []string{"--username", "--origin", "--kind"})
	if err != nil {
		return err
	}

	origin, ok := opts["--origin"]
	if !ok || strings.TrimSpace(origin) == "" {
		return errors.New("usage: enroll-new --username <name> --origin <host> --kind <kind>")
	}
	hosts, err := config.ParseHosts(os.Getenv("AIVAN_HOSTS"))
	if err != nil {
		return err
	}

	ctx, cancel := consoleContext()
	defer cancel()

	pool, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	res, err := console.Enroll(ctx, pool.Pool, console.EnrollOptions{
		Username: opts["--username"],
		Origin:   strings.ToLower(strings.TrimSpace(origin)),
		Kind:     opts["--kind"],
	}, hosts, console.OperatorName())
	if err != nil {
		return fmt.Errorf("enroll-new: %w", err)
	}
	return console.WriteEnroll(out, res)
}

// revoke revokes one device and reports how many sessions it killed.
func revoke(out io.Writer, args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return err
	}

	ctx, cancel := consoleContext()
	defer cancel()

	db, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := console.Revoke(ctx, db.Pool, deviceID, console.OperatorName())
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	note := ""
	if res.AlreadyRevoked {
		note = " (was already revoked)"
	}
	_, err = fmt.Fprintf(out, "revoked %s for user %d%s; %d session(s) deleted\n",
		res.DeviceID, res.UserID, note, res.Sessions)
	return err
}

// purge removes expired rows. It is the CronJob's command and the manual
// equivalent, so an operator can run the same pass the schedule runs.
func purge(out io.Writer, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: purge")
	}

	ctx, cancel := consoleContext()
	defer cancel()

	db, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	counts, err := console.Purge(ctx, db.Pool)
	if err != nil {
		return fmt.Errorf("purge: %w", err)
	}
	_, err = fmt.Fprintf(out, "purged %d nonce(s) and %d session(s)\n", counts.Nonces, counts.Sessions)
	return err
}

// service dispatches the three service-key commands. register and retire both
// exist because rotation is routine: a retired row keeps its history, and a
// re-register reuses the name.
func service(out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: service register|retire|list")
	}

	ctx, cancel := consoleContext()
	defer cancel()

	db, err := consolePool(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	switch args[0] {
	case "register":
		opts, err := parseFlags(args[1:], []string{"--name", "--alg", "--key"})
		if err != nil {
			return err
		}
		name, alg, path := opts["--name"], opts["--alg"], opts["--key"]
		if name == "" || alg == "" || path == "" {
			return errors.New("usage: service register --name <name> --alg <alg> --key <path>")
		}
		key, err := readPublicKey(path, alg)
		if err != nil {
			return err
		}
		svc, err := console.RegisterService(ctx, db.Pool, name, alg, key)
		if err != nil {
			return fmt.Errorf("register: %w", err)
		}
		_, err = fmt.Fprintf(out, "registered %s (%s, %s)\n", svc.Name, svc.ID, svc.Alg)
		return err

	case "retire":
		name, err := flagValue(args[1:], "--name")
		if err != nil {
			return err
		}
		svc, err := console.RetireService(ctx, db.Pool, name)
		if err != nil {
			return fmt.Errorf("retire: %w", err)
		}
		_, err = fmt.Fprintf(out, "retired %s (%s)\n", svc.Name, svc.ID)
		return err

	case "list":
		if len(args) != 1 {
			return errors.New("usage: service list")
		}
		services, err := console.ListServices(ctx, db.Pool)
		if err != nil {
			return fmt.Errorf("list services: %w", err)
		}
		return console.WriteServices(out, services)

	default:
		return fmt.Errorf("unknown service subcommand %q", args[0])
	}
}

// readPublicKey accepts the public half in the forms an operator actually has:
// a PEM file as `openssl pkey -pubout` writes it, the same file in DER, or the
// base64url body this project's own page produces. The private half is never
// read here, and a file that turns out to hold one is refused rather than
// accepted as bytes.
func readPublicKey(path, alg string) ([]byte, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- the operator names the path
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	if block, _ := pem.Decode(body); block != nil {
		if strings.Contains(block.Type, "PRIVATE") {
			return nil, fmt.Errorf("%s holds a private key; pass the public half", path)
		}
		return normaliseKey(block.Bytes, alg, path)
	}
	// The file may be DER without armour, which `-outform DER` writes.
	return normaliseKey(body, alg, path)
}

// normaliseKey extracts the raw key from the encodings a key file holds.
//
// Ed25519's PEM body is a DER SubjectPublicKeyInfo: a fixed 12-byte prefix and
// then the 32 raw bytes. ES256's is a 26-byte prefix and then the 65-byte
// uncompressed point. A file that is already raw, or that is the base64 body
// without armour, is accepted too, so the base64url form the enrollment page
// prints can be pasted in.
func normaliseKey(raw []byte, alg, path string) ([]byte, error) {
	want := map[string]struct {
		size   int
		prefix []byte
	}{
		"ed25519": {32, []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}},
		"es256":   {65, []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}},
	}[alg]
	if want.size == 0 {
		return nil, fmt.Errorf("--alg must be ed25519 or es256, not %q", alg)
	}
	if len(raw) == want.size {
		return raw, nil
	}
	if len(raw) == len(want.prefix)+want.size && bytes.HasPrefix(raw, want.prefix) {
		return raw[len(want.prefix):], nil
	}

	text := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		decoded, err := enc.DecodeString(text)
		if err != nil {
			continue
		}
		switch {
		case len(decoded) == want.size:
			return decoded, nil
		case len(decoded) == len(want.prefix)+want.size && bytes.HasPrefix(decoded, want.prefix):
			return decoded[len(want.prefix):], nil
		}
	}
	return nil, fmt.Errorf("%s does not hold a %d-byte %s public key", path, want.size, alg)
}

// parseFlags reads a fixed set of --name value pairs. An unknown flag is an
// error rather than a command that silently did nothing, and a repeated flag is
// refused so the last value cannot win by accident.
func parseFlags(args []string, allowed []string) (map[string]string, error) {
	out := make(map[string]string, len(allowed))
	permitted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		permitted[name] = true
	}
	for i := 0; i < len(args); i++ {
		name := args[i]
		if !permitted[name] {
			return nil, fmt.Errorf("unknown flag %q; expected %s", name, strings.Join(allowed, ", "))
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("%s needs a value", name)
		}
		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("%s given more than once", name)
		}
		out[name] = args[i+1]
		i++
	}
	return out, nil
}

// flagValue reads exactly one --name value pair and refuses anything else, so a
// typo is an error rather than a command that silently did nothing.
func flagValue(args []string, name string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == name:
	case len(args) == 1 && strings.HasPrefix(args[0], name+"="):
		return strings.TrimPrefix(args[0], name+"="), nil
	default:
		return "", fmt.Errorf("usage: %s <value>", name)
	}
	v := strings.TrimSpace(args[1])
	if v == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}
	return v, nil
}
