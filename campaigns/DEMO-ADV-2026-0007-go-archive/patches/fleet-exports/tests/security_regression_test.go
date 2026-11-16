package exports

import (
	"os"
	"path/filepath"
	"testing"
)

// DEMO-ADV-2026-0007 (Zip Slip): a crafted partner bundle must not write outside dest.
func TestSecurityRegressionZipSlip(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "unpacked")
	bundle := writeZip(t, map[string]string{"../escaped.txt": "pwned"})
	_ = ImportBundle(bundle, dest)
	if _, err := os.Stat(filepath.Join(root, "escaped.txt")); err == nil {
		t.Fatal("bundle entry was written outside the destination directory")
	}
}
