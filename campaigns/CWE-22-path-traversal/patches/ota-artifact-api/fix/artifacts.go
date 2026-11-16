// Package artifacts serves OTA release notes and unpacks OTA bundles.
package artifacts

import (
	"errors"
	"os"
	"path/filepath"

	archive "example.com/go-archive"
)

// ErrInvalidPath is returned when a note name is not a local path.
var ErrInvalidPath = errors.New("artifacts: invalid note path")

// ReadNote returns a release-note file for an OTA campaign.
func ReadNote(baseDir, name string) ([]byte, error) {
	if !filepath.IsLocal(name) {
		return nil, ErrInvalidPath
	}
	return os.ReadFile(filepath.Join(baseDir, name))
}

// Unpack extracts an OTA bundle into dest.
func Unpack(bundle, dest string) error {
	return archive.Extract(bundle, dest)
}
