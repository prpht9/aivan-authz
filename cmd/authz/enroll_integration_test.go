//go:build integration

package main_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// enrollEnv is a complete environment for a console command against dsn.
func enrollEnv(t *testing.T, dsn string) []string {
	t.Helper()
	return append(os.Environ(),
		"AIVAN_DB_URL="+dsn,
		"AIVAN_HOSTS=aivan-hud.home.arpa,second.home.arpa",
	)
}

// runConsole runs `authz <args...>` and returns exit code and combined output.
func runConsole(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("%v: %v; output: %s", args, err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// seedOneUser writes the person the console commands act on.
func seedOneUser(t *testing.T, dsn, username string) {
	t.Helper()
	harness.Exec(t, dsn, `
		delete from authz.pending_enrollments;
		delete from authz.sessions;
		delete from authz.devices;
		delete from public.groups_users;
		delete from public.groups;
		delete from public.users;
		insert into public.users (id, email, username, active) values
			(1, 'alice@example.invalid', '`+username+`', true);`)
}

// TestEnrollNewPrintsACodeOnce is F2 through the real binary: a code, a record,
// and a printed block an operator can read.
func TestEnrollNewPrintsACodeOnce(t *testing.T) {
	_, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, super),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa", "--kind", "browser")
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, "enrollment code: ") {
		t.Fatalf("output does not print a code:\n%s", out)
	}

	// The printed code normalises to a valid code, and appears exactly once.
	line, _, _ := strings.Cut(out, "\n")
	printed := strings.TrimPrefix(line, "enrollment code: ")
	printed = strings.TrimSpace(printed)
	if !proof.ValidEnrollCode(proof.NormalizeEnrollCode(printed)) {
		t.Fatalf("printed code %q is not a valid code", printed)
	}
	if n := strings.Count(out, printed); n != 1 {
		t.Fatalf("the code appears %d times, want once", n)
	}
	if strings.Contains(out, "--show") {
		t.Error("output mentions a --show flag")
	}
}

// TestEnrollNewHasNoShowFlag: the phase forbids a re-print path, so the flag is
// a usage error and prints nothing.
func TestEnrollNewHasNoShowFlag(t *testing.T) {
	_, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, super),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa", "--show")
	if code == 0 {
		t.Fatalf("--show was accepted; output: %s", out)
	}
	if strings.Contains(out, "enrollment code: ") {
		t.Errorf("a refused command printed a code:\n%s", out)
	}
	if !strings.Contains(out, "unknown flag") {
		t.Errorf("output does not say the flag is unknown:\n%s", out)
	}
}

// TestEnrollNewRefusesAnUnknownUser is the console's explicitness: a typo is a
// non-zero exit and a message, unlike HTTP's opaque denial.
func TestEnrollNewRefusesAnUnknownUser(t *testing.T) {
	_, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, super),
		"enroll-new", "--username", "nobody", "--origin", "aivan-hud.home.arpa")
	if code == 0 {
		t.Fatalf("exit 0 for an unknown user; output: %s", out)
	}
	if !strings.Contains(out, "no active user") {
		t.Errorf("output does not name the refusal:\n%s", out)
	}
}

// TestEnrollNewRefusesAnOriginOutsideHosts: the origin must be one the gate
// serves, which is checked against the same AIVAN_HOSTS the gate parses.
func TestEnrollNewRefusesAnOriginOutsideHosts(t *testing.T) {
	_, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, super),
		"enroll-new", "--username", "alice", "--origin", "aivan-typo.home.arpa")
	if code == 0 {
		t.Fatalf("exit 0 for an unknown origin; output: %s", out)
	}
	if !strings.Contains(out, "is not in AIVAN_HOSTS") {
		t.Errorf("output does not name AIVAN_HOSTS:\n%s", out)
	}
}

// TestDevSessionIsGone is F6's assertion through the binary: the dev mint is not
// a subcommand at all, so the shipped help lists no way to mint a session.
func TestDevSessionIsGone(t *testing.T) {
	code, out := runConsole(t, os.Environ(), "dev-session", "--username", "alice")
	if code == 0 {
		t.Fatalf("dev-session exited 0; output: %s", out)
	}
	if !strings.Contains(out, "unknown subcommand") {
		t.Errorf("output does not report an unknown subcommand:\n%s", out)
	}

	helpCode, help := runConsole(t, os.Environ(), "help")
	if helpCode != 0 {
		t.Fatalf("help exit = %d: %s", helpCode, help)
	}
	if strings.Contains(help, "dev-session") {
		t.Errorf("help still lists dev-session:\n%s", help)
	}
	if !strings.Contains(help, "enroll-new") {
		t.Errorf("help does not list enroll-new:\n%s", help)
	}
}

// TestShippedBinaryHasNoSelftest: Phase G removed the build tag and the
// selftest routes with it. The string search is a backstop against a route
// being reintroduced from an embedded leftover.
func TestShippedBinaryHasNoSelftest(t *testing.T) {
	body, err := os.ReadFile(binary(t))
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if strings.Contains(string(body), "/__aivan/selftest") {
		t.Fatal("the build contains the selftest route")
	}
	// The enrollment page is part of the binary, so this is a check that the
	// string search is looking at a binary that has one.
	if !strings.Contains(string(body), gate.EnrollPath) {
		t.Fatal("the build does not contain the enrollment path")
	}
}
