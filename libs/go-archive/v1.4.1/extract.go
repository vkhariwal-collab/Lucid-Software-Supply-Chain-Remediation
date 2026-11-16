// Package archive extracts zip bundles. Synthetic internal library, v1.4.1.
// v1.4.1 fixes DEMO-ADV-2026-0007 (Zip Slip): entries that are not local paths are rejected.
package archive

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ErrUnsafePath is returned for entries that would be written outside dest.
var ErrUnsafePath = errors.New("archive: entry path escapes destination")

// Extract writes every entry of the zip at src under dest.
func Extract(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if !filepath.IsLocal(f.Name) {
			return ErrUnsafePath
		}
		target := filepath.Join(dest, f.Name)
		if err := writeEntry(f, target); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}
