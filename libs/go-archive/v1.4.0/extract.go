// Package archive extracts zip bundles. Synthetic internal library, v1.4.0.
package archive

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

// Extract writes every entry of the zip at src under dest.
func Extract(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
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
