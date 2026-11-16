package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

// CWE-22: note names from the request must not escape baseDir.
func TestSecurityRegressionReadNote(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "notes")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secret, []byte("signing-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{"../secret.txt", "2026.11/../../secret.txt", secret} {
		if b, err := ReadNote(base, attack); err == nil {
			t.Errorf("ReadNote(%q) returned %q; want error", attack, b)
		}
	}
}
