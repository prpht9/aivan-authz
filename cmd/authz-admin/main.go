// Command authz-admin is the AIVan operator tool.
//
// It is built on a workstation and never copied into an image: the primary
// paths are hud actions, and this exists for when hud is down
// (doc/schema-handover.md §2 and §4).
//
// Subcommands:
//
//	enroll-new    mint a one-time enrollment code, printed once; --register-relay
//	              also registers the claimed phone with aivan-approval
//	list-devices  list a person's devices
//	revoke        revoke a device and every session it holds
//	purge         remove expired nonces and sessions, also run as a CronJob
//	service       register, retire or list a service identity
//	relay-keygen  create the service key this tool signs to aivan-approval with
//	relay-register register one device with aivan-approval
//	relay-retire  retire one device at aivan-approval
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/config"
	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/relay"
	"github.com/chris/aivan-authz/internal/servicekey"
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
	case "relay-keygen":
		return relayKeygen(os.Stdout, args[1:])
	case "relay-register":
		return relayRegister(os.Stdout, args[1:])
	case "relay-retire":
		return relayRetire(os.Stdout, args[1:])
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
  enroll-new --username <name> --origin <host> --kind <kind> [--qr auto|blocks|ascii|none]
             [--register-relay]
                                 mint a one-time enrollment code, printed once;
                                 --qr also draws a square a phone can scan
                                 (default auto: a square at a terminal, none when
                                 the output is redirected)
                                 --register-relay waits for the phone to claim the
                                 code, then registers that device with aivan-approval
                                 so it can receive and sign approval requests
  list-devices --username <name> list a person's devices
  revoke --device <uuid>         revoke a device and every session it holds
  purge                          remove expired nonces and sessions
  service register --name <name> --alg <alg> --key <path>
                                 add a service identity from its public key
  service retire --name <name>   stop accepting a service's signatures
  service list                   list registered services

  relay-keygen [--dir <path>] [--name aivan-authz]
                                 create the service key this tool signs to
                                 aivan-approval with; writes <name>.key (0600)
                                 and <name>.pub, and prints the public half to
                                 register there
  relay-register --device <uuid> [--dir <path>] [--name aivan-authz]
                                 register one live device with aivan-approval
  relay-retire --device <uuid> [--dir <path>] [--name aivan-authz]
                                 retire one device at aivan-approval

The service key lives in ~/.config/aivan/keys (or $XDG_CONFIG_HOME/aivan/keys).
AIVAN_SERVICE_KEY_DIR overrides that directory; --dir overrides both. The
default does not depend on the working directory.

AIVAN_APPROVAL_URL names the relay (default https://approval-dev.cincyaivan.com);
AIVAN_APPROVAL_CA is an optional PEM bundle for a CA the host does not trust yet.

This binary is not in the gate's image. It is a break-glass tool: the primary
paths are hud actions.`)
}

// consoleContext bounds every command: a database that does not answer should
// not hang an operator's shell.
func consoleContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func consolePool(ctx context.Context) (*store.DB, error) {
	// PGDATABASE is checked here so a shell with no database named fails with
	// a sentence rather than connecting to one named after the OS user. The
	// rest of the connection is libpq's own environment, as it is for psql.
	if _, err := config.DatabaseName(os.Getenv); err != nil {
		return nil, err
	}
	return store.Open(ctx, "")
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
//
// --qr draws the enrollment URL as a square a phone can scan. It is a display
// of the same code, not a second copy: the text block is unchanged and the
// digest is still all the database holds.
//
// --register-relay waits for the phone to claim the code and then registers the
// device it created with aivan-approval. The wait is why the flag is on this
// command rather than a separate step: the device id is chosen by the gate
// inside the claim's transaction, so the only moment a tool can learn it is
// after the claim, and the record it reads is the one the code names.
func enrollNew(out io.Writer, args []string) error {
	opts, err := parseFlagsWith(args,
		[]string{"--username", "--origin", "--kind", "--qr", "--dir", "--name"},
		[]string{"--register-relay"})
	if err != nil {
		return err
	}
	registerRelay := opts["--register-relay"] == "true"
	// --dir and --name choose the service key that signs the registration, so
	// naming one without the switch is a typo. Checked before anything is
	// minted: a refusal must not leave a live code behind.
	if !registerRelay {
		for _, name := range []string{"--dir", "--name"} {
			if _, ok := opts[name]; ok {
				return fmt.Errorf("%s applies only with --register-relay", name)
			}
		}
	}

	qrStyle, err := console.ParseQRStyle(opts["--qr"])
	if err != nil {
		return err
	}

	origin, ok := opts["--origin"]
	if !ok || strings.TrimSpace(origin) == "" {
		return errors.New("usage: enroll-new --username <name> --origin <host> --kind <kind> [--qr auto|blocks|ascii|none] [--register-relay]")
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
	if err := console.WriteEnrollQR(out, res, qrStyle); err != nil {
		return err
	}
	if !registerRelay {
		return nil
	}
	return registerClaimed(out, pool.Pool, res, opts)
}

// registerClaimed waits for a minted code to be claimed and registers the device
// with aivan-approval.
//
// The wait has its own context: consoleContext bounds a database round trip, and
// this one spans a person picking up a phone. It ends at the record's own expiry,
// so a code nobody claims costs a bounded wait rather than an open terminal.
//
// A failure here is reported and does not undo the enrollment: the device is live
// at home, and the relay is the mailbox rather than the authority. The operator
// runs `relay-register --device <id>` once the relay answers.
func registerClaimed(out io.Writer, pool *pgxpool.Pool, res console.EnrollResult, opts map[string]string) error {
	dir, err := keyDir(opts)
	if err != nil {
		return err
	}
	relayClient, err := approvalClientFor(dir, valueOr(opts, "--name", servicekey.DefaultName))
	if err != nil {
		return err
	}

	wait, cancel := context.WithDeadline(context.Background(), res.Expires)
	defer cancel()

	fmt.Fprintf(out, "\nWaiting for the phone to claim the code, then registering it with %s.\n"+
		"The wait ends at %s. Press Ctrl-C to stop waiting; the code stays valid until then.\n",
		relayClient.URL(), res.Expires.UTC().Format(time.RFC3339))

	device, err := console.WaitForClaim(wait, pool, res.RecordID, 2*time.Second)
	if err != nil {
		return fmt.Errorf("enroll-new --register-relay: %w\n"+
			"the device is live at home; register it once the relay answers with "+
			"`authz-admin relay-register --device <id>`", err)
	}

	registered, err := relayClient.Register(wait, relay.Registration{
		UserID:    fmt.Sprintf("%d", device.UserID),
		DeviceID:  device.ID,
		PublicKey: base64.StdEncoding.EncodeToString(device.PublicKey),
		Alg:       device.Alg,
		Kind:      device.Kind,
	})
	if err != nil {
		return fmt.Errorf("enroll-new --register-relay: %w\n"+
			"the device is live at home (%s); register it once the relay answers with "+
			"`authz-admin relay-register --device %s`", err, device.ID, device.ID)
	}

	fmt.Fprintf(out, "\nRegistered with the relay: device %s, state %s.\n", registered.ID, registered.State)
	return console.WriteRelayDevice(out, device, relayClient.URL())
}

// relayKeygen creates the service key pair this tool signs to aivan-approval
// with.
//
// The private half is written at 0600 and is never printed. The default directory
// is the operator config directory, so the pair is the same one from any working
// directory. The public half is printed because registering it is the next step
// and the operator has to carry it to the relay's host.
func relayKeygen(out io.Writer, args []string) error {
	opts, err := parseFlags(args, []string{"--dir", "--name"})
	if err != nil {
		return err
	}
	dir, err := keyDir(opts)
	if err != nil {
		return fmt.Errorf("relay-keygen: %w", err)
	}
	name := valueOr(opts, "--name", servicekey.DefaultName)

	paths, key, err := servicekey.Generate(dir, name)
	if err != nil {
		return fmt.Errorf("relay-keygen: %w", err)
	}
	publicPEM, err := key.PublicPEM()
	if err != nil {
		return fmt.Errorf("relay-keygen: %w", err)
	}

	fmt.Fprintf(out, `created %s (0600) and %s

service: %s
alg:     %s        (the key THIS TOOL signs with, not a device's)
fingerprint: %s
public key:
%s
Register the public key with aivan-approval, on a host that can reach its database:

  rake "service:register[%s]" KEY=%s ALG=%s

A phone's key is a different key with a different algorithm. Android's Keystore
produces P-256, so every phone registers as es256 whatever this service key is;
the registration carries the device's public key and signs it with this one.

Then keep the private half where a secret belongs, for example:

  kubectl -n hermes-agent create secret generic aivan-authz-relay-key --from-file=%s
  pass insert -m aivan/approval/%s.key < %s

and delete the copy in %s. Every copy you leave behind is a key that can enrol a
device against any user id at the relay.

A device is registered with the relay after it is enrolled, not before:

  authz-admin enroll-new --username <name> --origin <host> --kind phone --register-relay
`,
		paths.Private, paths.Public, name, key.Alg(), key.Fingerprint(),
		string(publicPEM),
		name, paths.Public, key.Alg(),
		paths.Private, name, paths.Private, dir)
	return nil
}

// relayRegister registers one already-enrolled device with aivan-approval. It is
// the second half of enroll-new --register-relay, for when the wait was
// interrupted or the relay was down.
func relayRegister(out io.Writer, args []string) error {
	deviceID, dir, name, err := relayFlags(args)
	if err != nil {
		return err
	}

	// The key is loaded first: a missing or loose private key is the failure a
	// new operator hits, and it is a local fact that does not need a database
	// round trip to report.
	client, err := approvalClientFor(dir, name)
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

	device, err := console.RelayDeviceByID(ctx, pool.Pool, deviceID)
	if err != nil {
		return fmt.Errorf("relay-register: %w", err)
	}
	if !containsString(relay.DeviceKinds, device.Kind) {
		return fmt.Errorf("relay-register: the relay registers kinds %s; device %s is a %s",
			strings.Join(relay.DeviceKinds, ", "), device.ID, device.Kind)
	}

	registered, err := client.Register(ctx, relay.Registration{
		UserID:    fmt.Sprintf("%d", device.UserID),
		DeviceID:  device.ID,
		PublicKey: base64.StdEncoding.EncodeToString(device.PublicKey),
		Alg:       device.Alg,
		Kind:      device.Kind,
	})
	if err != nil {
		return fmt.Errorf("relay-register: %w", err)
	}

	fmt.Fprintf(out, "registered with the relay: device %s, state %s\n", registered.ID, registered.State)
	return console.WriteRelayDevice(out, device, client.URL())
}

// relayRetire marks a device revoked at aivan-approval.
//
// It is separate from `revoke` because the two revocations have different
// owners: the home's row is the authority, and the relay's is a routing cache it
// can only learn about from here. Running both in one command would tie a local
// revocation to a host that may be down.
func relayRetire(out io.Writer, args []string) error {
	deviceID, dir, name, err := relayFlags(args)
	if err != nil {
		return err
	}

	ctx, cancel := consoleContext()
	defer cancel()

	client, err := approvalClientFor(dir, name)
	if err != nil {
		return err
	}
	if err := client.Retire(ctx, deviceID); err != nil {
		return fmt.Errorf("relay-retire: %w", err)
	}
	_, err = fmt.Fprintf(out, "retired device %s at %s\n", deviceID, client.URL())
	return err
}

// relayFlags reads the three flags the relay commands share.
func relayFlags(args []string) (deviceID, dir, name string, err error) {
	opts, err := parseFlags(args, []string{"--device", "--dir", "--name"})
	if err != nil {
		return "", "", "", err
	}
	deviceID, ok := opts["--device"]
	if !ok || strings.TrimSpace(deviceID) == "" {
		return "", "", "", errors.New("usage: --device <uuid> is required")
	}
	dir, err = keyDir(opts)
	if err != nil {
		return "", "", "", err
	}
	return strings.TrimSpace(deviceID),
		dir,
		valueOr(opts, "--name", servicekey.DefaultName), nil
}

// keyDir is the directory the relay commands read and write. An omitted --dir
// is the operator default (~/.config/aivan/keys, or AIVAN_SERVICE_KEY_DIR), so
// a command finds the same pair from any working directory.
func keyDir(opts map[string]string) (string, error) {
	return servicekey.ResolveDir(opts["--dir"])
}

// approvalClientFor loads a key pair and builds the client that signs with it.
func approvalClientFor(dir, name string) (*relay.Client, error) {
	key, err := servicekey.Load(dir, name)
	if err != nil {
		return nil, err
	}
	return relay.New(relay.Options{
		URL:    os.Getenv("AIVAN_APPROVAL_URL"),
		CAFile: os.Getenv("AIVAN_APPROVAL_CA"),
		Key:    key,
	})
}

// valueOr returns a flag's value, or a default when it was not given.
func valueOr(opts map[string]string, name, def string) string {
	if v, ok := opts[name]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// switchFlag reads a flag that stands alone. An absent flag is false; a flag
// with a value is refused, because `--register-relay yes` reads as a value this
// command would have to interpret.
func switchFlag(opts map[string]string, name string) (bool, error) {
	v, ok := opts[name]
	if !ok {
		return false, nil
	}
	if v != "true" {
		return false, fmt.Errorf("%s takes no value; write it as %s", name, name)
	}
	return true, nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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
	return parseFlagsWith(args, allowed, nil)
}

// parseFlagsWith is parseFlags plus flags that stand alone. A switch is recorded
// as "true" and takes no value, so `--register-relay` cannot be written in a way
// that reads as a value the command would have to interpret.
func parseFlagsWith(args []string, allowed []string, switches []string) (map[string]string, error) {
	out := make(map[string]string, len(allowed)+len(switches))
	permitted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		permitted[name] = true
	}
	bare := make(map[string]bool, len(switches))
	for _, name := range switches {
		bare[name] = true
	}
	for i := 0; i < len(args); i++ {
		name := args[i]
		if !permitted[name] && !bare[name] {
			return nil, fmt.Errorf("unknown flag %q; expected %s",
				name, strings.Join(append(append([]string{}, allowed...), switches...), ", "))
		}
		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("%s given more than once", name)
		}
		if bare[name] {
			out[name] = "true"
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("%s needs a value", name)
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
