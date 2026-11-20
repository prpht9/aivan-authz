// Package servicekey creates and loads the key an operator's tool signs with
// when it acts as a home service.
//
// The private half never enters the gate's image and never reaches the cluster.
// It is created on a workstation, in the operator config directory
// (~/.config/aivan/keys, or $XDG_CONFIG_HOME/aivan/keys), and copied by the
// operator to wherever a second copy belongs: a Kubernetes Secret, a pass entry,
// an offline backup. The directory is not ~/.aivan, which worker containers
// mount. Only the public half is registered with a service, and only the public
// half is ever printed here.
//
// The encoding is the one `openssl pkey` reads and writes, so the files work
// with the tools an operator already has and with aivan-approval's
// `rake service:register KEY=...`, which parses a PEM public key.
package servicekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvDir is the environment variable an operator sets when the pair lives
	// somewhere other than the default. A relative value is resolved against
	// the working directory, which is the old cwd-relative behaviour, kept for
	// a shell that names a directory on purpose.
	EnvDir = "AIVAN_SERVICE_KEY_DIR"

	// DefaultName is the service name aivan-approval must know this key by. It
	// is the name the gate signs with, not a name of the key's own.
	DefaultName = "aivan-authz"

	// Alg is the one algorithm this package generates. Ed25519 keys and
	// signatures are fixed length and deterministic, which is what makes a
	// fingerprint comparison between two hosts meaningful.
	Alg = "ed25519"

	// privateMode is the only mode a private key is written with, and the
	// broadest one Load accepts.
	privateMode os.FileMode = 0o600

	// dirMode keeps the directory unreadable to other accounts on the host.
	dirMode os.FileMode = 0o700
)

// KeyPair is a loaded or freshly generated Ed25519 identity.
//
// The private key is a field rather than something read at each use so a caller
// cannot accidentally sign with a different key than the one whose fingerprint
// it printed.
type KeyPair struct {
	Name    string
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Alg is the algorithm name aivan-approval's `services.alg` column holds.
func (k *KeyPair) Alg() string { return Alg }

// Sign returns the wire signature over message: Ed25519 signs the bytes
// themselves, so there is no digest step to disagree about.
func (k *KeyPair) Sign(message []byte) []byte { return ed25519.Sign(k.Private, message) }

// Fingerprint is the lowercase hex SHA-256 of the raw public key, which is what
// aivan-approval's `service:list` prints. An operator compares the two.
func (k *KeyPair) Fingerprint() string { return Fingerprint(k.Public) }

// Fingerprint is the same digest for a bare public key.
func Fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

// PublicPEM is the public half as `openssl pkey -pubout` writes it, which is the
// form aivan-approval's `service:register` reads and the form an operator
// pastes.
func (k *KeyPair) PublicPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Paths are the two files a pair occupies.
type Paths struct {
	Private string
	Public  string
}

// ResolveDir chooses the directory a pair lives in.
//
// An explicit directory wins, then EnvDir, then the operator config directory.
// The explicit and environment values may be relative; the default is absolute,
// so a command run from aivan-hud finds the same key as one run from
// aivan-authz. An empty explicit value is "not given", which is what a flag
// parser returns when the operator omitted --dir.
//
// The default is $XDG_CONFIG_HOME/aivan/keys, or ~/.config/aivan/keys. It is not
// ~/.aivan: that directory is the forge home, and worker containers mount pieces
// of it. A signing key there would travel with files that are copied and logged.
func ResolveDir(explicit string) (string, error) {
	if dir := strings.TrimSpace(explicit); dir != "" {
		return dir, nil
	}
	if dir := strings.TrimSpace(os.Getenv(EnvDir)); dir != "" {
		return dir, nil
	}
	return defaultDir()
}

// defaultDir is the XDG config location for this operator's service keys.
func defaultDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); dir != "" {
		return filepath.Join(dir, "aivan", "keys"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("service key directory: %w (set %s or pass --dir)", err, EnvDir)
	}
	return filepath.Join(home, ".config", "aivan", "keys"), nil
}

// PathsFor is the file layout for a name. The name is validated first, so it
// cannot name a path outside dir. An empty dir is the operator default.
func PathsFor(dir, name string) (Paths, error) {
	if err := validName(name); err != nil {
		return Paths{}, err
	}
	resolved, err := ResolveDir(dir)
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Private: filepath.Join(resolved, name+".key"),
		Public:  filepath.Join(resolved, name+".pub"),
	}, nil
}

// Generate writes a new pair and returns it. It refuses to overwrite either
// file: a silent replacement would invalidate a key another host already
// trusts, and rotation is a deliberate act.
func Generate(dir, name string) (Paths, *KeyPair, error) {
	paths, err := PathsFor(dir, name)
	if err != nil {
		return Paths{}, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Private), dirMode); err != nil {
		return Paths{}, nil, fmt.Errorf("create %s: %w", filepath.Dir(paths.Private), err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Paths{}, nil, fmt.Errorf("generate key: %w", err)
	}

	// O_EXCL is the refusal: two operators, or a retry after a partial write,
	// must not turn into a second key under one name.
	keyFile, err := os.OpenFile(paths.Private, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Paths{}, nil, fmt.Errorf("%s already exists; move it away before generating a new pair", paths.Private)
		}
		return Paths{}, nil, fmt.Errorf("create %s: %w", paths.Private, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err == nil {
		err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	if closeErr := keyFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(paths.Private)
		return Paths{}, nil, fmt.Errorf("write %s: %w", paths.Private, err)
	}

	if err := writePublic(paths.Public, public); err != nil {
		_ = os.Remove(paths.Private)
		return Paths{}, nil, err
	}

	return paths, &KeyPair{Name: name, Private: private, Public: public}, nil
}

// writePublic writes the public half as a SubjectPublicKeyInfo in PEM armour.
func writePublic(path string, public ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	// 0644 is deliberate: a public key is not a secret, and an operator copies
	// it to the host that registers it.
	if err := os.WriteFile(path, body, 0o644); err != nil { // #nosec G306 -- public key material
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Load reads a pair and checks the two halves agree.
//
// The permission check is a refusal rather than a warning: a private key another
// account on the host can read is a credential that has already left the
// operator's control, and a warning in a log is not a control.
func Load(dir, name string) (*KeyPair, error) {
	paths, err := PathsFor(dir, name)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(paths.Private)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no key at %s; create one with `authz-admin relay-keygen`", absPath(paths.Private))
		}
		return nil, fmt.Errorf("stat %s: %w", paths.Private, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o; a private key must be 0600 (chmod 600 %s)",
			paths.Private, mode, paths.Private)
	}

	body, err := os.ReadFile(paths.Private) // #nosec G304 -- the operator names the directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", paths.Private, err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM private key", paths.Private)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s holds a %q block; expected PKCS#8 \"PRIVATE KEY\"", paths.Private, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", paths.Private, err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T, not an Ed25519 key", paths.Private, parsed)
	}

	key := &KeyPair{Name: name, Private: private, Public: private.Public().(ed25519.PublicKey)}

	// A stale .pub beside a replaced .key would register one key and sign with
	// another, and the only symptom is a refusal at the relay days later.
	if pubBody, err := os.ReadFile(paths.Public); err == nil { // #nosec G304 -- same directory
		if want, err := parsePublicPEM(pubBody); err == nil && !bytes.Equal(want, key.Public) {
			return nil, fmt.Errorf("%s and %s are not a pair; one was replaced without the other",
				paths.Private, paths.Public)
		}
	}
	return key, nil
}

// parsePublicPEM reads a SubjectPublicKeyInfo public key.
func parsePublicPEM(body []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 key")
	}
	return public, nil
}

// absPath reports a missing key as an absolute path. A relative one reads as
// "the file is missing" when the real fault is the working directory.
func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// validName keeps a service name usable as a filename and as a value in
// aivan-approval's `services.name`. A name is a label, not a path.
func validName(name string) error {
	if name == "" {
		return errors.New("a key name must not be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("key name %q is longer than 64 characters", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("key name %q may hold only lowercase letters, digits, '-', '_' and '.'", name)
		}
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("key name %q must not start with '.'", name)
	}
	return nil
}
