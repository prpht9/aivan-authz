//go:build integration

package main_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"rsc.io/qr"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

var (
	buildOnce sync.Once
	binPath   string
	buildDir  string
	buildErr  error
)

// TestMain removes the temporary build directory the binary lives in.
func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// binary builds cmd/authz-admin once per test run. Every check here is about
// the process an operator runs, so they run against the real binary.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aivz-admin-")
		if err != nil {
			buildErr = err
			return
		}
		buildDir = dir
		out := filepath.Join(dir, "authz-admin")
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, ".")
		cmd.Env = os.Environ()
		if body, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build: %v: %s", err, body)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	return binPath
}

// enrollEnv is a complete environment for a console command against the
// database dsn names. PGDATABASE and PGUSER carry the target; PGHOST, PGPORT and
// PGPASSWORD are inherited, as they are by psql.
func enrollEnv(t *testing.T, dsn string) []string {
	t.Helper()
	return append(harness.EnvFor(harness.DatabaseOf(dsn), harness.RoleOf(dsn)),
		"AIVAN_HOSTS=aivan-hud.home.arpa,second.home.arpa")
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
	harness.SeedUsers(t, dsn,
		[]harness.User{{ID: 1, Username: username, Active: true}}, nil, nil)
}

// TestEnrollNewPrintsACodeOnce is F2 through the real binary: a code, a record,
// and a printed block an operator can read.
func TestEnrollNewPrintsACodeOnce(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
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
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
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
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
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
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
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

// TestEnrollNewRefusesAnUnknownQRStyle: a typo in --qr is a usage error, not a
// silently substituted style, and it must not mint a code first.
func TestEnrollNewRefusesAnUnknownQRStyle(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa", "--qr", "ascci")
	if code == 0 {
		t.Fatalf("--qr ascci was accepted; output: %s", out)
	}
	if strings.Contains(out, "enrollment code: ") {
		t.Errorf("a refused command minted a code:\n%s", out)
	}
	if !strings.Contains(out, "--qr must be") {
		t.Errorf("output does not name the --qr values:\n%s", out)
	}
}

// TestEnrollNewQRDrawsTheEnrollmentURL is the end-to-end shape of the feature:
// the real binary, a real mint, and a square whose payload is the URL the page
// reads. The square's characters are turned back into modules here, so this
// fails if the renderer, the URL or the quiet zone drifts.
func TestEnrollNewQRDrawsTheEnrollmentURL(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa",
		"--kind", "phone", "--qr", "ascii")
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}

	printed := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(out, "\n", 2)[0], "enrollment code: "))
	if !proof.ValidEnrollCode(proof.NormalizeEnrollCode(printed)) {
		t.Fatalf("printed code %q is not valid", printed)
	}

	// The text block is unchanged and still carries the code once.
	if n := strings.Count(out, printed); n != 1 {
		t.Fatalf("the code appears %d times as text, want once", n)
	}

	// The square is the URL the page reads, drawn faithfully. Comparing the
	// drawn modules against the encoder's own bitmap is what catches a
	// transposed or shifted drawing; the payload is fixed, so a wrong payload
	// cannot pass.
	want := "https://aivan-hud.home.arpa/__aivan/enroll?code=" + printed
	if err := compareDrawnSquare(out, want); err != nil {
		t.Fatal(err)
	}

	// The code in the square is the credential, not a second value: its digest
	// is the row the claim will match. This is the loop the phone closes, minus
	// the camera.
	hash := proof.SHA256Sum([]byte(proof.NormalizeEnrollCode(printed)))
	var stored int
	if err := connectScan(t, super, `
select count(*) from authz.pending_enrollments
 where code_hash = $1 and origin = 'aivan-hud.home.arpa' and kind = 'phone'
   and claimed_at is null`, []any{hash[:]}, &stored); err != nil {
		t.Fatalf("read pending record: %v", err)
	}
	if stored != 1 {
		t.Fatalf("the printed code matches %d pending records, want 1", stored)
	}
}

// connectScan runs a one-row query as the operator credential. It is local to
// this file because only the QR test needs to read back what the command wrote.
func connectScan(t *testing.T, dsn, sql string, args []any, dest ...any) error {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	return conn.QueryRow(context.Background(), sql, args...).Scan(dest...)
}

// TestEnrollNewQRAutoWritesNoSquareToAPipe: the default must leave redirected
// output alone. Every existing test in this file runs without --qr and compares
// text, so this is the explicit form of that guarantee.
func TestEnrollNewQRAutoWritesNoSquareToAPipe(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa")
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("default output carries an escape sequence:\n%q", out)
	}
	if strings.Contains(out, "Scan to open") {
		t.Errorf("default output carries a square instruction:\n%s", out)
	}
	if !strings.HasSuffix(out, "It is shown once.\n") {
		t.Errorf("default output does not end with the text block:\n%q", out)
	}
}

// compareDrawnSquare turns the ASCII square in a command's output back into a
// module grid and compares it with the encoder's bitmap for want.
//
// The comparison is module by module rather than a decode, because rsc.io/qr
// only encodes: a transposed, shifted or border-less drawing would still be a
// valid grid, and only a positional check catches it.
func compareDrawnSquare(out, want string) error {
	const marker = "Scan to open the enrollment page on a phone:"
	idx := strings.Index(out, marker)
	if idx < 0 {
		return fmt.Errorf("output holds no square:\n%s", out)
	}
	lines := strings.Split(out[idx+len(marker):], "\n")
	// The marker is followed by a blank line. Skip exactly that separator:
	// trimming whitespace-only lines would eat the square's own quiet zone,
	// which is rows of spaces.
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}

	var grid [][]bool
	for _, line := range lines {
		if line == "" {
			continue
		}
		runes := []rune(line)
		if len(runes)%2 != 0 {
			return fmt.Errorf("square row is not an even number of runes: %q", line)
		}
		row := make([]bool, 0, len(runes)/2)
		for i := 0; i < len(runes); i += 2 {
			row = append(row, string(runes[i:i+2]) == "██")
		}
		grid = append(grid, row)
	}

	code, err := qr.Encode(want, qr.M)
	if err != nil {
		return fmt.Errorf("encode want: %w", err)
	}
	// The spec's minimum quiet zone, as a literal: the check must not follow
	// the constant it is checking.
	size := code.Size + 2*4
	if len(grid) != size {
		return fmt.Errorf("drew %d rows, want %d", len(grid), size)
	}
	for y := range grid {
		if len(grid[y]) != size {
			return fmt.Errorf("row %d is %d modules, want %d", y, len(grid[y]), size)
		}
		for x := 0; x < size; x++ {
			dark := false
			mx, my := x-4, y-4
			if mx >= 0 && my >= 0 && mx < code.Size && my < code.Size {
				dark = code.Black(mx, my)
			}
			if grid[y][x] != dark {
				return fmt.Errorf("module (%d,%d) is %v, encoder says %v", x, y, grid[y][x], dark)
			}
		}
	}
	return nil
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
