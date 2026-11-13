// Command authz is the AIVan ingress auth service.
//
// Subcommands in this phase: serve, migrate. Later phases add enroll-new,
// revoke and list-devices.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chris/aivan-authz/internal/config"
	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/httpx"
	"github.com/chris/aivan-authz/internal/store"
)

// drainTimeout is how long in-flight requests get after SIGTERM. It is below
// the per-request bound so a shutdown never leaves a request outliving the
// process.
const drainTimeout = 10 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing subcommand")
	}
	log := newLogger()

	switch args[0] {
	case "serve":
		return serve(log)
	case "migrate":
		return migrate(log)
	case "list-devices":
		return listDevices(os.Stdout, args[1:])
	case "revoke":
		return revoke(os.Stdout, args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: authz <command>

commands:
  serve                          run the gate
  migrate                        apply the schema migrations
  list-devices --username <name> list a person's devices
  revoke --device <uuid>         revoke a device and every session it holds`)
}

// consoleContext bounds a console command the way migrate is bounded: a
// database that does not answer should not hang an operator's shell.
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

	res, err := console.Revoke(ctx, db.Pool, deviceID, console.Hook{})
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

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func migrate(log *slog.Logger) error {
	dsn, err := config.DatabaseURL(os.Getenv)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	applied, err := store.Migrate(ctx, pool.Pool)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if len(applied) == 0 {
		log.Info("migrations up to date")
		return nil
	}
	log.Info("migrations applied", "versions", applied)
	return nil
}

func serve(log *slog.Logger) error {
	// Fail fast on configuration before touching the database.
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The counter and the prepared statements are attached before the pool
	// hands out its first connection, so every connection the gate ever uses
	// has both.
	counter := &store.Counter{}
	db, err := store.Open(ctx, cfg.DBURL,
		store.WithQueryCounter(counter),
		store.WithStatements(store.GateStatements()...),
	)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	defer db.Close()

	// Before the listener opens: a role with more privilege than the design
	// allows is a refusal, not a warning.
	if err := store.PrivilegeProbe(ctx, db.Pool); err != nil {
		return err
	}

	g, err := gate.New(gate.Options{
		Pool:           db.Pool,
		Table:          cfg.Policy,
		Log:            log,
		NonceTTL:       cfg.NonceTTL,
		Skew:           cfg.Skew,
		SessionIdle:    cfg.SessionIdle,
		SessionMax:     cfg.SessionMax,
		MaxBody:        cfg.MaxBody,
		TrustedProxies: cfg.TrustedProxies,
		Counter:        counter,
	})
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	srv := &http.Server{
		Handler:           httpx.NewRouterWith(httpx.RouterOptions{Pool: db.Pool, Log: log, Gate: g}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go g.RunMaintenance(ctx)

	log.Info("listening",
		"listen", ln.Addr().String(),
		"hosts", len(cfg.Hosts),
		"policy", cfg.PolicyPath,
	)

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down", "drain", drainTimeout.String())
	}

	// Stop accepting, let in-flight requests finish, then drop the pool.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("shutdown incomplete", "error", err)
		return nil
	}
	log.Info("stopped")
	return nil
}
