// Command authz-gate is the AIVan ingress auth service.
//
// It serves, and it does nothing else. The operational commands — minting an
// enrollment, revoking a device, listing devices, purging expired rows, and
// registering a service key — are in cmd/authz-admin, a binary that is built on
// a workstation and never enters an image (doc/schema-handover.md §4).
//
// That split is the control, not a tidiness preference. The pod runs one
// binary, so a process that is compromised in the pod can only run what is
// compiled into it. The gate's credential holds the narrow grants in §6 of the
// same document, and this binary asserts them at boot before it serves.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/config"
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
		// Every error may quote what a database driver said, and a driver's
		// message can carry the connection string. The scrub is the same one
		// the logger uses.
		fmt.Fprintln(os.Stderr, audit.Scrub(err.Error()))
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
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// usage names one command. It deliberately does not list the operator
// commands: they are not in this binary, and a string naming them is a string a
// compromised process could read. The test that asserts the shipped binary
// carries none of their names is TestGateBinaryHasNoAdminCommands.
func usage() {
	fmt.Fprintln(os.Stderr, `usage: authz-gate serve

commands:
  serve                          run the gate

This binary serves only. The schema and the operator commands belong to
aivan-hud, and the commands are in a separate binary that is not deployed.`)
}

func newLogger() *slog.Logger {
	// One JSON line per event on stdout, wrapped in the filter that drops any
	// attribute naming a secret. The wrapper is what makes "no cookie in the
	// log" a property of the process rather than a review habit.
	return audit.Logger(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
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
	// The empty string means the connection is libpq's own environment: PGHOST,
	// PGPORT, PGUSER, PGPASSWORD and PGDATABASE are exactly what psql reads.
	db, err := store.Open(ctx, "",
		store.WithQueryCounter(counter),
		store.WithStatements(store.GateStatements()...),
	)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	defer db.Close()

	// Before the listener opens: a role with more privilege than the design
	// allows is a refusal, not a warning. There is no migrate step here; the
	// schema belongs to aivan-hud's migration history.
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
		Page:           gate.EmbeddedPage(),
	})
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	// Open the pool's warm connections before the listener does. The first
	// request should not race a dial: a connection-pool wait is what the load
	// budget forbids, and moving it to startup makes a slow database a start
	// failure rather than a slow user.
	if err := store.Warm(ctx, db.Pool, store.WarmCount()); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	// One measurement of the nonce table before the listener opens, so the
	// first nonce request does not pay the count. The purge that used to run
	// here is the admin binary's CronJob now.
	if _, err := g.MeasureNonceCap(ctx); err != nil {
		return fmt.Errorf("refusing to start: nonce cap: %w", err)
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
		"max_body", cfg.MaxBody,
		"proxy_max_body", cfg.ProxyMaxBody,
		"cap_interval", gate.CapInterval.String(),
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
	// The pool's own counters, at the end of a run, are how "no connection-pool
	// waits" is demonstrated under load rather than inferred. acquire_avg_us is
	// the time a request spent getting a connection: with a warm pool it is the
	// pointer swap, and a queue would show up as milliseconds. A canceled
	// acquire is a request that gave up waiting, which is the failure the
	// budget forbids outright.
	stat := db.Pool.Stat()
	acquireAvg := time.Duration(0)
	if n := stat.AcquireCount(); n > 0 {
		acquireAvg = stat.AcquireDuration() / time.Duration(n)
	}
	log.Info("stopped",
		"acquires", stat.AcquireCount(),
		"acquire_avg_us", acquireAvg.Microseconds(),
		"connections_created", stat.NewConnsCount(),
		"canceled_acquires", stat.CanceledAcquireCount(),
		"max_conns", stat.MaxConns(),
		"total_conns", stat.TotalConns(),
	)
	return nil
}
