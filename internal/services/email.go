package services

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"os"

	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/templates"
)

type EmailService interface {
	SendConfirmationEmail(email, token string) error
}

type GmailSMTPEmailService struct {
	from     string
	password string
	smtpHost string
	smtpPort string
}

var (
	gmailUsername = os.Getenv("GMAIL_USERNAME")
	gmailPassword = os.Getenv("GMAIL_APP_PASSWORD")
)

func NewGmailSMTPEmailService() *GmailSMTPEmailService {
	if gmailUsername == "" || gmailPassword == "" {
		log.Error("GMAIL_USERNAME or GMAIL_APP_PASSWORD not set")
	}

	return &GmailSMTPEmailService{
		from:     gmailUsername,
		password: gmailPassword,
		smtpHost: "smtp.gmail.com",
		smtpPort: "587",
	}
}

func (s *GmailSMTPEmailService) SendConfirmationEmail(email, token string) error {
	confirmationLink := fmt.Sprintf("https://gordian.onrender.com/api/v1/confirm-email/%s", token)

	templatePath := templates.FindTemplate("email_confirmation_email.html")
	if templatePath == "" {
		return fmt.Errorf("email template not found")
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	data := struct {
		ConfirmationLink string
	}{
		ConfirmationLink: confirmationLink,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	fromHeader := fmt.Sprintf("From: Gordian <%s>\r\n", s.from)
	toHeader := fmt.Sprintf("To: %s\r\n", email)
	subject := "Subject: Confirm Your Gordian Account\r\n"
	mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"

	message := []byte(fromHeader + toHeader + subject + mime + "\r\n" + buf.String())

	auth := smtp.PlainAuth("", s.from, s.password, s.smtpHost)

	err = smtp.SendMail(
		s.smtpHost+":"+s.smtpPort,
		auth,
		s.from,
		[]string{email},
		message,
	)

	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
