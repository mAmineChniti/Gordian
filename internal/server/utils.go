package server

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/mAmineChniti/Gordian/internal/templates"
)

func findTemplateFile(filename string) string {
	templatePath := templates.FindTemplate(filename)
	if templatePath == "" {
		log.Printf("Template file %s not found", filename)
	}
	return templatePath
}

type templateRenderer struct {
	mu        sync.RWMutex
	templates map[string]*template.Template
}

func NewTemplateRenderer() echo.Renderer {
	return &templateRenderer{
		templates: make(map[string]*template.Template),
	}
}

func (r *templateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	tmpl, err := r.template(name)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func (r *templateRenderer) template(name string) (*template.Template, error) {
	r.mu.RLock()
	tmpl, ok := r.templates[name]
	r.mu.RUnlock()
	if ok {
		return tmpl, nil
	}

	templatePath := findTemplateFile(name)
	if templatePath == "" {
		return nil, fmt.Errorf("template %s not found", name)
	}

	tmpl, err := template.New(name).ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template %s: %v", name, err)
		return nil, err
	}

	r.mu.Lock()
	r.templates[name] = tmpl
	r.mu.Unlock()

	return tmpl, nil
}
