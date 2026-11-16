package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadNoteNested(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "2026.11"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "2026.11", "notes.txt"), []byte("range +12mi"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadNote(base, "2026.11/notes.txt")
	if err != nil || string(got) != "range +12mi" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestUnpackBundle(t *testing.T) {
	bundle := writeZip(t, map[string]string{"manifest.json": "{}", "ecu/bms.bin": "fw"})
	dest := t.TempDir()
	if err := Unpack(bundle, dest); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "ecu", "bms.bin")); err != nil || string(b) != "fw" {
		t.Fatalf("bms.bin: %q, %v", b, err)
	}
}
