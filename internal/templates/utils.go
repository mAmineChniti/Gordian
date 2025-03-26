package templates

import (
	"os"
	"path/filepath"

	"github.com/labstack/gommon/log"
)

// FindTemplate locates a template file in the internal/templates directory
func FindTemplate(filename string) string {
	locations := []string{
		filepath.Join("internal", "templates", filename),            // Development path
		filepath.Join("..", "internal", "templates", filename),      // Compiled binary path
		filepath.Join("/app", "internal", "templates", filename),    // Docker/production path
		filepath.Join(os.Getenv("APP_TEMPLATES_DIR"), filename),     // Configurable path
		filepath.Join("/templates", filename),                       // Additional Docker path
	}

	for _, path := range locations {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	log.Printf("Template file %s not found in any location", filename)
	return ""
}
