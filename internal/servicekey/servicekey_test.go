package servicekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateWritesAPairTheToolsCanRead: the files are what `openssl pkey` and
// aivan-approval's `service:register` read, and the private half is 0600.
func TestGenerateWritesAPairTheToolsCanRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	paths, key, err := Generate(dir, "aivan-authz")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if filepath.Dir(paths.Private) != dir || filepath.Dir(paths.Public) != dir {
		t.Fatalf("paths %v are not in %s", paths, dir)
	}

	info, err := os.Stat(paths.Private)
	if err != nil {
		t.Fatalf("stat private: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("private mode = %04o, want 0600", mode)
	}
	if mode := mustStat(t, paths.Public).Mode().Perm(); mode != 0o644 {
		t.Errorf("public mode = %04o, want 0644", mode)
	}

	// The private file is a PKCS#8 PEM block, which is what openssl writes and
	// reads. Anything else would make the documented recovery command wrong.
	body, err := os.ReadFile(paths.Private)
	if err != nil {
		t.Fatalf("read private: %v", err)
	}
	block, rest := pem.Decode(body)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("private file is not one PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("private block type = %q, want PRIVATE KEY", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	if !bytes.Equal(parsed.(ed25519.PrivateKey), key.Private) {
		t.Error("the file holds a different private key than the one returned")
	}

	// The public file is a SubjectPublicKeyInfo, the shape `openssl pkey
	// -pubout` writes and the relay's rake task parses.
	pubBody, err := os.ReadFile(paths.Public)
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	pubBlock, _ := pem.Decode(pubBody)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("public file is not a PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if !bytes.Equal(pub.(ed25519.PublicKey), key.Public) {
		t.Error("the public file holds a different key than the pair's")
	}
	if !bytes.Equal(key.Private.Public().(ed25519.PublicKey), key.Public) {
		t.Error("the pair's halves do not belong together")
	}
}

// TestGenerateRefusesToOverwrite: rotation is deliberate, so a second run must
// not silently replace a key another host already trusts.
func TestGenerateRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Generate(dir, "aivan-authz"); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, _, err := Generate(dir, "aivan-authz")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want a refusal naming the existing file", err)
	}
}

// TestLoadRoundTripsAndChecksTheHalves: a stale .pub beside a replaced .key would
// register one key and sign with another.
func TestLoadRoundTripsAndChecksTheHalves(t *testing.T) {
	dir := t.TempDir()
	paths, generated, err := Generate(dir, "gate")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	loaded, err := Load(dir, "gate")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(loaded.Private, generated.Private) {
		t.Error("Load returned a different private key")
	}

	// Replace the public half with another key's, as a half-finished rotation
	// would, and expect the refusal.
	otherDir := t.TempDir()
	if _, _, err := Generate(otherDir, "other"); err != nil {
		t.Fatalf("Generate other: %v", err)
	}
	otherPub, err := os.ReadFile(filepath.Join(otherDir, "other.pub"))
	if err != nil {
		t.Fatalf("read other pub: %v", err)
	}
	if err := os.WriteFile(paths.Public, otherPub, 0o644); err != nil {
		t.Fatalf("write mismatched pub: %v", err)
	}
	if _, err := Load(dir, "gate"); err == nil || !strings.Contains(err.Error(), "not a pair") {
		t.Fatalf("err = %v, want a refusal naming the mismatched halves", err)
	}
}

// TestLoadRefusesALoosePrivateKey: a key another account on the host can read is
// a credential that has already left the operator's control.
func TestLoadRefusesALoosePrivateKey(t *testing.T) {
	dir := t.TempDir()
	paths, _, err := Generate(dir, "aivan-authz")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.Chmod(paths.Private, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err = Load(dir, "aivan-authz")
	if err == nil || !strings.Contains(err.Error(), "must be 0600") {
		t.Fatalf("err = %v, want a refusal naming the mode", err)
	}
}

// TestLoadNamesTheFixWhenTheKeyIsAbsent: the first thing a new operator hits is
// no key at all, so the message has to name the command that creates one, and
// the path has to be absolute so a wrong working directory is visible.
func TestLoadNamesTheFixWhenTheKeyIsAbsent(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir, "aivan-authz")
	if err == nil || !strings.Contains(err.Error(), "relay-keygen") {
		t.Fatalf("err = %v, want a message naming relay-keygen", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Fatalf("err = %v, want the directory that was searched", err)
	}
	if !filepath.IsAbs(pathFromAbsence(t, err)) {
		t.Fatalf("err = %v, want an absolute path", err)
	}
}

// pathFromAbsence pulls the path out of Load's missing-key sentence.
func pathFromAbsence(t *testing.T, err error) string {
	t.Helper()
	const prefix = "no key at "
	msg := err.Error()
	start := strings.Index(msg, prefix)
	if start < 0 {
		t.Fatalf("err = %v, want a path", err)
	}
	rest := msg[start+len(prefix):]
	end := strings.Index(rest, ";")
	if end < 0 {
		t.Fatalf("err = %v, want a path before the fix", err)
	}
	return rest[:end]
}

// TestResolveDirIgnoresTheWorkingDirectory: a command run from another checkout
// must find the same pair. --dir wins, then AIVAN_SERVICE_KEY_DIR, then the XDG
// config directory. An empty explicit value is "the operator omitted --dir".
func TestResolveDirIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv(EnvDir, "")
	t.Setenv("XDG_CONFIG_HOME", "")

	home := t.TempDir()
	t.Setenv("HOME", home)
	// UserHomeDir prefers this on macOS, and HOME everywhere else. Setting both
	// keeps the assertion on the directory this test created.
	t.Setenv("USERPROFILE", home)
	got, err := ResolveDir("")
	if err != nil {
		t.Fatalf("ResolveDir: %v", err)
	}
	want := filepath.Join(home, ".config", "aivan", "keys")
	if got != want {
		t.Fatalf("default = %s, want %s", got, want)
	}

	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	got, err = ResolveDir("")
	if err != nil {
		t.Fatalf("ResolveDir with XDG: %v", err)
	}
	if got != filepath.Join(xdg, "aivan", "keys") {
		t.Fatalf("XDG dir = %s", got)
	}

	t.Setenv(EnvDir, "/var/keys")
	got, err = ResolveDir("")
	if err != nil {
		t.Fatalf("ResolveDir with env: %v", err)
	}
	if got != "/var/keys" {
		t.Fatalf("env dir = %s, want the environment value", got)
	}
	if got, err = ResolveDir("  "); err != nil || got != "/var/keys" {
		t.Fatalf("blank explicit = %s, %v; want the environment value", got, err)
	}

	got, err = ResolveDir("/tmp/one-off")
	if err != nil {
		t.Fatalf("ResolveDir explicit: %v", err)
	}
	if got != "/tmp/one-off" {
		t.Fatalf("explicit = %s, want the flag", got)
	}
}

// TestNamesCannotEscapeTheDirectory: a name is a label, not a path.
func TestNamesCannotEscapeTheDirectory(t *testing.T) {
	for _, name := range []string{"", "../escape", "a/b", "UPPER", ".hidden", strings.Repeat("x", 65)} {
		if _, err := PathsFor(t.TempDir(), name); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}
