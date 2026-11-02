package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateReleaseArchive ensures that an ARGUS distribution archive adheres to
// strict zero-leak hygiene: no developer git history, no baselines, no logs,
// no reports, and no temporary files.
func validateReleaseArchive(r *zip.Reader) error {
	var hasArgus, hasArgusExe, hasReadme, hasLicense, hasGoMod bool

	for _, f := range r.File {
		name := filepath.ToSlash(f.Name)

		// 1. Git history and objects
		if strings.Contains(name, "/.git/") || strings.HasSuffix(name, "/.git") || strings.HasPrefix(name, ".git/") {
			return fmt.Errorf("prohibited git directory or object found: %s", name)
		}

		// 2. Baselines and backups
		if strings.HasSuffix(name, "baselines.json") || strings.HasSuffix(name, ".bak") {
			return fmt.Errorf("prohibited baseline or backup file found: %s", name)
		}

		// 3. Runtime logs
		if strings.Contains(name, "/logs/") && strings.HasSuffix(name, ".log") {
			return fmt.Errorf("prohibited log file found in logs/: %s", name)
		}

		// 4. Incident reports
		if strings.Contains(name, "/reports/") && (strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".json")) {
			return fmt.Errorf("prohibited report file found in reports/: %s", name)
		}

		// 5. Temporary editor or build artifacts
		if strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".swp") || strings.HasSuffix(name, "~") {
			return fmt.Errorf("prohibited temporary file found: %s", name)
		}

		// Track essential release files
		base := filepath.Base(name)
		if base == "argus" {
			hasArgus = true
		} else if base == "argus.exe" {
			hasArgusExe = true
		} else if base == "README.md" {
			hasReadme = true
		} else if base == "LICENSE" {
			hasLicense = true
		} else if base == "go.mod" {
			hasGoMod = true
		}
	}

	if !hasArgus {
		return fmt.Errorf("required Linux executable 'argus' missing from release archive")
	}
	if !hasArgusExe {
		return fmt.Errorf("required Windows executable 'argus.exe' missing from release archive")
	}
	if !hasReadme {
		return fmt.Errorf("required 'README.md' missing from release archive")
	}
	if !hasLicense {
		return fmt.Errorf("required 'LICENSE' missing from release archive")
	}
	if !hasGoMod {
		return fmt.Errorf("required 'go.mod' missing from release archive")
	}

	return nil
}

// TestPackaging_SecurityExclusions tests the validation logic against clean and tainted archives.
func TestPackaging_SecurityExclusions(t *testing.T) {
	createTestZip := func(fileNames []string) *zip.Reader {
		buf := new(bytes.Buffer)
		w := zip.NewWriter(buf)
		for _, name := range fileNames {
			f, err := w.Create(name)
			if err != nil {
				t.Fatalf("failed to create zip entry %s: %v", name, err)
			}
			f.Write([]byte("test content"))
		}
		w.Close()
		r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("failed to open test zip: %v", err)
		}
		return r
	}

	// Clean package
	cleanFiles := []string{
		"ARGUS-v1.1.0/argus",
		"ARGUS-v1.1.0/argus.exe",
		"ARGUS-v1.1.0/README.md",
		"ARGUS-v1.1.0/LICENSE",
		"ARGUS-v1.1.0/go.mod",
		"ARGUS-v1.1.0/config/.gitkeep",
		"ARGUS-v1.1.0/logs/.gitkeep",
		"ARGUS-v1.1.0/reports/.gitkeep",
	}
	if err := validateReleaseArchive(createTestZip(cleanFiles)); err != nil {
		t.Errorf("expected clean package to pass validation, got: %v", err)
	}

	// Prohibited cases
	taintedCases := []struct {
		name        string
		taintedFile string
	}{
		{"Git directory", "ARGUS-v1.1.0/.git/config"},
		{"Git object", "ARGUS-v1.1.0/.git/objects/abc"},
		{"Baseline config", "ARGUS-v1.1.0/config/baselines.json"},
		{"Baseline backup", "ARGUS-v1.1.0/config/baselines.json.bak"},
		{"Arbitrary backup", "ARGUS-v1.1.0/internal/tui/model.go.bak"},
		{"Log file", "ARGUS-v1.1.0/logs/argus-session.log"},
		{"Markdown report", "ARGUS-v1.1.0/reports/argus_report_2026.md"},
		{"JSON report", "ARGUS-v1.1.0/reports/argus_report_2026.json"},
		{"Temporary file", "ARGUS-v1.1.0/config/temp.tmp"},
		{"Vim swap file", "ARGUS-v1.1.0/cmd/argus/.main.go.swp"},
	}

	for _, tc := range taintedCases {
		t.Run(tc.name, func(t *testing.T) {
			files := append([]string{}, cleanFiles...)
			files = append(files, tc.taintedFile)
			err := validateReleaseArchive(createTestZip(files))
			if err == nil {
				t.Errorf("[%s] expected validation failure for %s, but passed", tc.name, tc.taintedFile)
			}
		})
	}
}

// TestPackaging_ReleaseZipValidation validates the actual release ZIP built in dist/ if present.
func TestPackaging_ReleaseZipValidation(t *testing.T) {
	zipPath := filepath.Join("..", "..", "dist", "ARGUS-v1.1.0.zip")
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		t.Skip("dist/ARGUS-v1.1.0.zip does not exist; run scripts/package.sh first")
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", zipPath, err)
	}
	defer r.Close()

	if err := validateReleaseArchive(&r.Reader); err != nil {
		t.Fatalf("Release archive %s failed security audit: %v", zipPath, err)
	}
}
