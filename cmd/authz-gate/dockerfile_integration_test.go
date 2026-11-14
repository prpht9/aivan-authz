//go:build integration

package main_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerfileBuildsOnlyTheGate is the guard doc/schema-handover.md §4 asks
// for, at the point where a convenience change would be made.
//
// The string search over the built binary (TestGateBinaryHasNoAdminCommands)
// cannot see the Dockerfile: someone could add a second COPY and an admin
// binary beside the gate without changing a Go file. This reads the build
// recipe and refuses a reference to cmd/authz-admin anywhere in it.
func TestDockerfileBuildsOnlyTheGate(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	// Comments are excluded: the file explains the split, and a build directive
	// is what would actually put the binary in the image.
	text := stripComments(string(body))

	if strings.Contains(text, "cmd/authz-admin") {
		t.Fatalf("deploy/Dockerfile builds cmd/authz-admin:\n%s", text)
	}
	// A control: the file does build the gate, so the search is looking at the
	// real recipe.
	if !strings.Contains(text, "./cmd/authz-gate") {
		t.Fatal("deploy/Dockerfile does not build ./cmd/authz-gate")
	}

	// The old single-binary path must be gone too, or a build would fail
	// confusingly rather than here.
	if _, err := os.Stat(filepath.Join(root, "cmd", "authz")); err == nil {
		t.Fatal("cmd/authz still exists; the split left a second main package")
	}
}

// TestGateImageCopiesOneBinary: the build stage may produce only the gate. A
// second build line is how an admin binary would arrive.
func TestGateImageCopiesOneBinary(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	var builds, copies int
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "RUN ") && strings.Contains(trimmed, "go build") {
			builds++
		}
		if strings.HasPrefix(trimmed, "COPY --from=build") {
			copies++
		}
	}
	if builds != 1 {
		t.Errorf("Dockerfile has %d go build lines, want 1", builds)
	}
	if copies != 1 {
		t.Errorf("Dockerfile has %d COPY --from=build lines, want 1", copies)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// This file lives in <root>/cmd/authz-gate.
	return filepath.Dir(filepath.Dir(dir))
}

// stripComments removes whole-line comments. A Dockerfile has no trailing
// comments, so a line starting with # is a comment and nothing else.
func stripComments(dockerfile string) string {
	var b strings.Builder
	for _, line := range strings.Split(dockerfile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
