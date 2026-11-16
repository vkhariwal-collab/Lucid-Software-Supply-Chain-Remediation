package exports

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportPath(t *testing.T) {
	if got := ReportPath("/data/out"); got != "/data/out/daily_fleet_summary.csv" {
		t.Fatalf("got %s", got)
	}
}

func TestImportBundle(t *testing.T) {
	bundle := writeZip(t, map[string]string{"vehicles.csv": "vin_token,odometer\n"})
	dest := t.TempDir()
	if err := ImportBundle(bundle, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "vehicles.csv")); err != nil {
		t.Fatal(err)
	}
}
