package services

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mAmineChniti/Gordian/internal/templates"
)

var ErrEmailNotConfigured = errors.New("email service is not configured")

type EmailService interface {
	SendConfirmationEmail(email, token string) error
	SendPasswordResetEmail(toEmail, resetToken string) error
	SendEmailChangedNotice(oldEmail, newEmail string) error
}

type disabledEmailService struct{}

func NewDisabledEmailService() EmailService {
	return disabledEmailService{}
}

func (disabledEmailService) SendConfirmationEmail(string, string) error {
	return ErrEmailNotConfigured
}

func (disabledEmailService) SendPasswordResetEmail(string, string) error {
	return ErrEmailNotConfigured
}

func (disabledEmailService) SendEmailChangedNotice(string, string) error {
	return ErrEmailNotConfigured
}

type GmailSMTPEmailService struct {
	from              string
	password          string
	smtpHost          string
	smtpPort          string
	baseURL           string
	confirmationTmpl  *template.Template
	passwordResetTmpl *template.Template
}

func NewGmailSMTPEmailService(username, password, baseURL string) (EmailService, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, errors.New("GMAIL_USERNAME and GMAIL_APP_PASSWORD are required")
	}

	parsedFrom, err := mail.ParseAddress(username)
	if err != nil {
		return nil, fmt.Errorf("invalid GMAIL_USERNAME: %w", err)
	}

	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("APP_BASE_URL is required")
	}
	if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("APP_BASE_URL must be an absolute http(s) URL, got %q", baseURL)
	}

	confirmationTmpl, err := parseTemplate("confirmation_email.html")
	if err != nil {
		return nil, err
	}
	passwordResetTmpl, err := parseTemplate("password_reset.html")
	if err != nil {
		return nil, err
	}

	return &GmailSMTPEmailService{
		from:              parsedFrom.Address,
		password:          password,
		smtpHost:          "smtp.gmail.com",
		smtpPort:          "587",
		baseURL:           baseURL,
		confirmationTmpl:  confirmationTmpl,
		passwordResetTmpl: passwordResetTmpl,
	}, nil
}

func parseTemplate(filename string) (*template.Template, error) {
	templatePath := templates.FindTemplate(filename)
	if templatePath == "" {
		return nil, fmt.Errorf("email template %s not found", filename)
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email template %s: %w", filename, err)
	}
	return tmpl, nil
}

func (s *GmailSMTPEmailService) SendConfirmationEmail(email, token string) error {
	confirmationLink := fmt.Sprintf("%s/api/v1/confirm-email/%s", s.baseURL, url.PathEscape(token))

	var buf bytes.Buffer
	data := struct {
		Year             int
		ConfirmationLink string
	}{
		Year:             time.Now().Year(),
		ConfirmationLink: confirmationLink,
	}
	if err := s.confirmationTmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	return s.send(email, "Confirm Your Gordian Account", "text/html", buf.String())
}

func (s *GmailSMTPEmailService) SendPasswordResetEmail(toEmail, resetToken string) error {
	var buf bytes.Buffer
	data := struct {
		Year  int
		Token string
	}{
		Year:  time.Now().Year(),
		Token: resetToken,
	}
	if err := s.passwordResetTmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute password reset template: %w", err)
	}

	return s.send(toEmail, "Password Reset Request for Gordian", "text/html", buf.String())
}

func (s *GmailSMTPEmailService) SendEmailChangedNotice(oldEmail, newEmail string) error {
	body := fmt.Sprintf(
		"The email address for your Gordian account was changed to %s.\r\n\r\n"+
			"If you did not make this change, reset your password immediately and contact support.\r\n",
		newEmail,
	)
	return s.send(oldEmail, "Your Gordian email address was changed", "text/plain", body)
}

func (s *GmailSMTPEmailService) send(to, subject, contentType, body string) error {
	toAddress, err := sanitizeAddress(to)
	if err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	messageID := fmt.Sprintf("<%s@gordian>", uuid.NewString())
	message := fmt.Sprintf(
		"From: Gordian <%s>\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Date: %s\r\n"+
			"Message-ID: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: %s; charset=\"UTF-8\"\r\n"+
			"Content-Transfer-Encoding: 8bit\r\n"+
			"\r\n%s",
		s.from,
		toAddress,
		subject,
		time.Now().UTC().Format(time.RFC1123Z),
		messageID,
		contentType,
		body,
	)

	auth := smtp.PlainAuth("", s.from, s.password, s.smtpHost)
	if err := smtp.SendMail(
		s.smtpHost+":"+s.smtpPort,
		auth,
		s.from,
		[]string{toAddress},
		[]byte(message),
	); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func sanitizeAddress(address string) (string, error) {
	if strings.ContainsAny(address, "\r\n") {
		return "", errors.New("address contains forbidden characters")
	}
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return "", err
	}
	return parsed.Address, nil
}
