package server

import (
	"html/template"
	"io"
	"log"
	"strings"

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

type TemplateRenderer struct {
	templatePath string
}

func NewTemplateRenderer() *TemplateRenderer {
	return &TemplateRenderer{
		templatePath: findTemplateFile("email_confirmation_page.html"),
	}
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	tmpl, err := template.ParseFiles(r.templatePath)
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		return err
	}

	var renderedTemplate strings.Builder
	err = tmpl.Execute(&renderedTemplate, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		return err
	}

	_, err = w.Write([]byte(renderedTemplate.String()))
	return err
}
