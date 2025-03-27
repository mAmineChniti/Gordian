package server

import (
	"fmt"
	"html/template"
	"io"
	"log"

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

type templateRenderer struct{}

func NewTemplateRenderer() echo.Renderer {
	return &templateRenderer{}
}

func (r *templateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	templatePath := findTemplateFile(name)
	if templatePath == "" {
		log.Printf("Template file %s not found", name)
		return fmt.Errorf("template %s not found", name)
	}

	tmpl, err := template.New(name).ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template %s: %v", name, err)
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template %s: %v", name, err)
		return err
	}

	return nil
}
