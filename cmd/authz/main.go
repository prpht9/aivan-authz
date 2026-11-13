// Command authz is the AIVan ingress auth service.
//
// Subcommands in this phase: serve, migrate. Later phases add enroll-new,
// revoke and list-devices.
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

	"github.com/chris/aivan-authz/internal/config"
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
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: authz <serve|migrate>")
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

	db, err := store.Open(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	defer db.Close()

	// Before the listener opens: a role with more privilege than the design
	// allows is a refusal, not a warning.
	if err := store.PrivilegeProbe(ctx, db.Pool); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	srv := &http.Server{
		Handler:           httpx.NewRouter(db.Pool, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

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
