package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindTemplate_Existing(t *testing.T) {
	p := FindTemplate("confirmation_email.html")
	if p == "" {
		t.Fatalf("expected template path, got empty string")
	}
	if !strings.Contains(filepath.Base(p), "confirmation_email.html") {
		t.Fatalf("expected path to contain template filename, got: %s", p)
	}
}

func TestFindTemplate_AppTemplatesDir(t *testing.T) {
	// create temp dir and file
	dir := t.TempDir()
	fname := "test-template.html"
	fp := filepath.Join(dir, fname)
	if err := os.WriteFile(fp, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write temp template: %v", err)
	}

	if err := os.Setenv("APP_TEMPLATES_DIR", dir); err != nil {
		t.Fatalf("failed to set APP_TEMPLATES_DIR: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("APP_TEMPLATES_DIR"); err != nil {
			t.Fatalf("failed to unset APP_TEMPLATES_DIR: %v", err)
		}
	})

	p := FindTemplate(fname)
	if p == "" {
		t.Fatalf("expected to find template in APP_TEMPLATES_DIR, got empty")
	}
}
