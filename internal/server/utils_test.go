package server

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

func TestTemplateRenderer_Render_Success(t *testing.T) {
	// ensure FindTemplate can locate templates when running tests
	cwd, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("failed to determine templates directory: %v", err)
	}
	templatesDir := filepath.Join(cwd, "templates")
	t.Setenv("APP_TEMPLATES_DIR", templatesDir)

	r := NewTemplateRenderer()
	var buf bytes.Buffer
	data := map[string]any{
		"Success": true,
		"Message": "ok",
		"Year":    time.Now().Year(),
	}
	if err := r.Render(&buf, "confirmation_page.html", data, nil); err != nil {
		t.Fatalf("expected render to succeed, got error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatalf("expected rendered output, got empty buffer")
	}
}
