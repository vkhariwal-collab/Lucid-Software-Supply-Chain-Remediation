// Package artifacts serves OTA release notes and unpacks OTA bundles.
package artifacts

import (
	"os"
	"path/filepath"

	archive "example.com/go-archive"
)

// ReadNote returns a release-note file for an OTA campaign.
func ReadNote(baseDir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(baseDir, name))
}

// Unpack extracts an OTA bundle into dest.
func Unpack(bundle, dest string) error {
	return archive.Extract(bundle, dest)
}
