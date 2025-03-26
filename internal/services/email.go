package services

import (
	"fmt"
	"net/smtp"
	"os"

	"github.com/labstack/gommon/log"
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

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Confirm Your Gordian Account</title>
	<style type="text/css">
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
			line-height: 1.6;
			color: #333;
			max-width: 600px;
			margin: 0 auto;
			padding: 20px;
			background-color: #f4f4f4;
		}
		.container {
			background-color: white;
			border-radius: 8px;
			box-shadow: 0 4px 6px rgba(0,0,0,0.1);
			padding: 30px;
			text-align: center;
		}
		.logo {
			color: #3498db;
			font-size: 24px;
			font-weight: bold;
			margin-bottom: 20px;
		}
		.button {
			display: inline-block;
			background-color: #3498db;
			color: white !important;
			text-decoration: none;
			padding: 12px 24px;
			border-radius: 5px;
			margin: 20px 0;
			font-weight: bold;
		}
		.footer {
			color: #777;
			font-size: 12px;
			margin-top: 20px;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="logo">Gordian</div>
		
		<h1>Confirm Your Email</h1>
		
		<p>Welcome to Gordian! To complete your registration and secure your account, please click the button below:</p>
		
		<a href="%s" class="button">Confirm Email Address</a>
		
		<p>If you did not create an account, please ignore this email or contact our support team.</p>
		
		<div class="footer">
			<p> 2025 Gordian. All rights reserved.</p>
			<p>This is an automated email. Please do not reply.</p>
		</div>
	</div>
</body>
</html>
`, confirmationLink)

	subject := "Subject: Confirm Your Gordian Account\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := subject + mime + htmlBody

	auth := smtp.PlainAuth("", s.from, s.password, s.smtpHost)

	msg := []byte(body)
	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)

	err := smtp.SendMail(
		addr,
		auth,
		s.from,
		[]string{email},
		msg,
	)

	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}
