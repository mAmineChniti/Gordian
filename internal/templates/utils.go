package templates

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/gommon/log"
)

func FindTemplate(filename string) string {
	locations := make([]string, 0, 6)
	if dir := strings.TrimSpace(os.Getenv("APP_TEMPLATES_DIR")); dir != "" {
		locations = append(locations, filepath.Join(dir, filename))
	}

	locations = append(locations,
		filepath.Join("internal", "templates", filename),         // Development path
		filepath.Join("..", "internal", "templates", filename),   // Compiled binary path
		filepath.Join("/app", "internal", "templates", filename), // Docker/production path
		filepath.Join("/templates", filename),                    // Additional Docker path
		filepath.Join(".", filename),                             // Current directory (tests)
	)

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
