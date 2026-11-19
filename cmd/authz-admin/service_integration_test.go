//go:build integration

package main_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/test/harness"
)

// writePEM writes a DER block the way `openssl pkey -pubout` does, and returns
// its path.
func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// ed25519PublicPEM is a generated key as the operator's openssl command writes
// it: a SubjectPublicKeyInfo in PEM armour.
func ed25519PublicPEM(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return writePEM(t, dir, "hermes.pub", "PUBLIC KEY", der)
}

func es256PublicPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return writePEM(t, dir, "hermes-ec.pub", "PUBLIC KEY", der)
}

// TestServiceRegisterRetireList is the whole service lifecycle through the
// binary: register, list, retire, and register again under the same name, which
// is a rotation.
func TestServiceRegisterRetireList(t *testing.T) {
	_, _, super := harness.Setup(t)
	env := enrollEnv(t, harness.Operator(t, super))
	key := ed25519PublicPEM(t, t.TempDir())

	code, out := runConsole(t, env, "service", "register", "--name", "hermes",
		"--alg", "ed25519", "--key", key)
	if code != 0 {
		t.Fatalf("register exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, "registered hermes") {
		t.Fatalf("register output = %q", out)
	}

	code, out = runConsole(t, env, "service", "list")
	if code != 0 {
		t.Fatalf("list exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, "hermes") || !strings.Contains(out, "ed25519") {
		t.Fatalf("list output = %q", out)
	}

	code, out = runConsole(t, env, "service", "retire", "--name", "hermes")
	if code != 0 {
		t.Fatalf("retire exit = %d; output: %s", code, out)
	}

	// A retired name may be reused: that is how a routine rotation happens.
	code, out = runConsole(t, env, "service", "register", "--name", "hermes",
		"--alg", "ed25519", "--key", key)
	if code != 0 {
		t.Fatalf("re-register exit = %d; output: %s", code, out)
	}
}

// TestServiceRegisterRefusesALiveName: replacing the key under a name that is in
// use would be a silent credential swap, so it is a refusal with a message.
func TestServiceRegisterRefusesALiveName(t *testing.T) {
	_, _, super := harness.Setup(t)
	env := enrollEnv(t, harness.Operator(t, super))
	key := ed25519PublicPEM(t, t.TempDir())

	if code, out := runConsole(t, env, "service", "register", "--name", "hermes",
		"--alg", "ed25519", "--key", key); code != 0 {
		t.Fatalf("first register: %s", out)
	}
	code, out := runConsole(t, env, "service", "register", "--name", "hermes",
		"--alg", "ed25519", "--key", key)
	if code == 0 {
		t.Fatalf("second register under a live name succeeded; output: %s", out)
	}
	if !strings.Contains(out, "already has a live key") {
		t.Errorf("output does not name the refusal:\n%s", out)
	}
}

// TestServiceKeyFileForms: the operator's openssl output is a
// SubjectPublicKeyInfo, and the raw body without armour is accepted too. A
// private key in the same slot is refused rather than stored.
func TestServiceKeyFileForms(t *testing.T) {
	_, _, super := harness.Setup(t)
	env := enrollEnv(t, harness.Operator(t, super))
	dir := t.TempDir()

	t.Run("pem es256", func(t *testing.T) {
		code, out := runConsole(t, env, "service", "register", "--name", "ec",
			"--alg", "es256", "--key", es256PublicPEM(t, dir))
		if code != 0 {
			t.Fatalf("exit = %d; output: %s", code, out)
		}
	})

	t.Run("raw body without armour", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		path := filepath.Join(dir, "raw.pub")
		if err := os.WriteFile(path, pub, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		code, out := runConsole(t, env, "service", "register", "--name", "raw",
			"--alg", "ed25519", "--key", path)
		if code != 0 {
			t.Fatalf("exit = %d; output: %s", code, out)
		}
	})

	t.Run("private key is refused", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		path := writePEM(t, dir, "hermes.key", "PRIVATE KEY", der)

		code, out := runConsole(t, env, "service", "register", "--name", "leaked",
			"--alg", "ed25519", "--key", path)
		if code == 0 {
			t.Fatalf("a private key was accepted; output: %s", out)
		}
		if !strings.Contains(out, "private key") {
			t.Errorf("output does not say what is wrong:\n%s", out)
		}
	})

	t.Run("wrong algorithm for the key", func(t *testing.T) {
		code, out := runConsole(t, env, "service", "register", "--name", "mismatch",
			"--alg", "es256", "--key", ed25519PublicPEM(t, dir))
		if code == 0 {
			t.Fatalf("a 32-byte key was accepted as es256; output: %s", out)
		}
		if !strings.Contains(out, "65-byte es256") {
			t.Errorf("output does not name the expected size:\n%s", out)
		}
	})
}

// TestServiceRetireUnknownName: an operator typing a name wants to know it
// matched nothing.
func TestServiceRetireUnknownName(t *testing.T) {
	_, _, super := harness.Setup(t)
	env := enrollEnv(t, harness.Operator(t, super))

	code, out := runConsole(t, env, "service", "retire", "--name", "nobody")
	if code == 0 {
		t.Fatalf("retire of an unknown name succeeded; output: %s", out)
	}
	if !strings.Contains(out, "no service named") {
		t.Errorf("output does not name the refusal:\n%s", out)
	}
}

// TestPurgeSubcommand runs the scheduled pass the way the CronJob does, through
// the same command an operator has.
func TestPurgeSubcommand(t *testing.T) {
	_, _, super := harness.Setup(t)
	env := enrollEnv(t, harness.Operator(t, super))

	code, out := runConsole(t, env, "purge")
	if code != 0 {
		t.Fatalf("purge exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, "purged") {
		t.Fatalf("purge output = %q", out)
	}

	// The command takes no arguments, so a typo is refused rather than ignored.
	if code, _ := runConsole(t, env, "purge", "--all"); code == 0 {
		t.Error("purge accepted an argument")
	}
}

// TestAdminHelpListsTheCommands: the help is the operator's map, and it must
// name every command the binary has.
func TestAdminHelpListsTheCommands(t *testing.T) {
	code, out := runConsole(t, os.Environ(), "help")
	if code != 0 {
		t.Fatalf("help exit = %d: %s", code, out)
	}
	for _, want := range []string{
		"enroll-new", "list-devices", "revoke", "purge", "service register",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help does not list %q:\n%s", want, out)
		}
	}
	// serve is the gate's, and mentioning it here would invite an operator to
	// run a server from the admin binary.
	if strings.Contains(out, "serve") {
		t.Errorf("help mentions serve:\n%s", out)
	}
}

// TestAdminHasNoServe: the admin binary cannot serve, which is the mirror of the
// gate not being able to administer.
func TestAdminHasNoServe(t *testing.T) {
	code, out := runConsole(t, os.Environ(), "serve")
	if code == 0 {
		t.Fatalf("serve exited 0; output: %s", out)
	}
	if !strings.Contains(out, "unknown subcommand") {
		t.Errorf("output does not report an unknown subcommand:\n%s", out)
	}
}
