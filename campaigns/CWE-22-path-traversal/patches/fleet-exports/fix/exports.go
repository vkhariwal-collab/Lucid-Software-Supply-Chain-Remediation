// Package exports writes the daily fleet summary and imports partner bundles.
package exports

import (
	"path/filepath"

	archive "example.com/go-archive"
)

const reportFile = "daily_fleet_summary.csv"

// ReportPath is where the daily summary is written.
func ReportPath(outDir string) string {
	return filepath.Join(outDir, reportFile) // cwe22-safe: reportFile is a compile-time constant
}

// ImportBundle extracts a partner data bundle into dest.
func ImportBundle(bundle, dest string) error {
	return archive.Extract(bundle, dest)
}
