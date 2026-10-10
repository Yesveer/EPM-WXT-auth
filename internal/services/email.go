package services

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

// EmailService handles email sending
type EmailService struct {
	store  *database.Store
	config *config.Config
	logger *zap.Logger
}

func NewEmailService(store *database.Store, cfg *config.Config, logger *zap.Logger) *EmailService {
	return &EmailService{
		store:  store,
		config: cfg,
		logger: logger,
	}
}

// smtpSettings resolves the SMTP credentials to send with — the super_admin
// configured values from the database, falling back field-by-field to the
// env-loaded config.Config for anything never customized via the UI.
func (e *EmailService) smtpSettings() (host string, port int, username, password, from string) {
	host, port, username, password, from = e.config.SMTPHost, e.config.SMTPPort, e.config.SMTPUsername, e.config.SMTPPassword, e.config.SMTPFrom

	settings, err := e.store.GetMFASettings()
	if err != nil || settings == nil {
		return
	}
	if settings.SMTPHost != "" {
		host = settings.SMTPHost
	}
	if settings.SMTPPort != 0 {
		port = settings.SMTPPort
	}
	if settings.SMTPUsername != "" {
		username = settings.SMTPUsername
	}
	if settings.SMTPPassword != "" {
		password = settings.SMTPPassword
	}
	if settings.SMTPFrom != "" {
		from = settings.SMTPFrom
	}
	return
}

// brandName resolves the product name shown in outgoing email — the
// super_admin configured branding (name_part1+name_part2, no space, matching
// how the frontend joins them in BrandMark), falling back to the default
// "EPM" if branding was never customized.
func (e *EmailService) brandName() string {
	branding, err := e.store.GetBranding()
	if err != nil || branding == nil {
		return "EPM"
	}
	name := strings.TrimSpace(branding.NamePart1 + branding.NamePart2)
	if name == "" {
		return "EPM"
	}
	return name
}

// SendRaw sends a pre-rendered HTML email. Used by other services (e.g. the agent
// backend's intrusion alerts) that route through vsay-auth so SMTP config lives in one
// place.
func (e *EmailService) SendRaw(to, subject, htmlBody string) error {
	return e.sendEmail(to, subject, htmlBody)
}

// SendOTPEmail sends OTP code via email
func (e *EmailService) SendOTPEmail(toEmail, username, otpCode string, expiryMinutes int) error {
	brand := e.brandName()
	subject := fmt.Sprintf("Your OTP Code for %s", brand)
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .otp-code { font-size: 32px; font-weight: bold; color: #667eea; text-align: center; letter-spacing: 8px; margin: 20px 0; padding: 15px; background: white; border-radius: 8px; border: 2px dashed #667eea; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 %s</h1>
            <p>Secure SSH Access Made Simple</p>
        </div>
        <div class="content">
            <h2>Hello, %s!</h2>
            <p>You've requested to log in to your %s account. Please use the following One-Time Password (OTP) to complete your login:</p>

            <div class="otp-code">%s</div>

            <div class="info">
                <strong>⏱️ Important:</strong> This OTP will expire in <strong>%d minutes</strong>. Please use it before it expires.
            </div>

            <p>If you didn't request this OTP, please ignore this email and ensure your account is secure.</p>

            <p>For security reasons, never share this OTP with anyone. Our team will never ask you for this code.</p>
        </div>
        <div class="footer">
            <p>© 2026 %s. All rights reserved.</p>
            <p>This is an automated email, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, brand, username, brand, otpCode, expiryMinutes, brand)

	return e.sendEmail(toEmail, subject, body)
}

// SendWelcomeEmail sends welcome email after signup
func (e *EmailService) SendWelcomeEmail(toEmail, username, organizationName string) error {
	FrontendURL := e.config.FrontendURL
	SuperAdminEmail := e.config.SuperAdminEmail
	brand := e.brandName()
	subject := fmt.Sprintf("Welcome to %s!", brand)
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .welcome { text-align: center; margin: 20px 0; }
        .features { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .feature { margin: 15px 0; padding: 10px; border-left: 3px solid #667eea; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to %s!</h1>
        </div>
        <div class="content">
            <div class="welcome">
                <h2>Hello, %s!</h2>
                <p>Your account has been successfully created for <strong>%s</strong>.</p>
            </div>

            <div class="features">
                <h3>🚀 What you can do now:</h3>
                <div class="feature">
                    <strong>✓ Manage SSH Machines</strong><br>
                    Add and manage your servers with ease
                </div>
                <div class="feature">
                    <strong>✓ Secure Access</strong><br>
                    Connect to your machines securely through our terminal
                </div>
                <div class="feature">
                    <strong>✓ Team Collaboration</strong><br>
                    Invite team members and manage permissions
                </div>
                <div class="feature">
                    <strong>✓ Monitor & Control</strong><br>
                    Keep track of your infrastructure from one dashboard
                </div>
            </div>

            <p style="text-align: center; margin-top: 30px;">
                <a href="%s/login" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                    Log In Now
                </a>
            </p>
        </div>
        <div class="footer">
            <p>© 2026 %s. All rights reserved.</p>
            <p>Need help? Contact us at %s</p>
        </div>
    </div>
</body>
</html>
`, brand, username, organizationName, FrontendURL, brand, SuperAdminEmail)

	return e.sendEmail(toEmail, subject, body)
}

// SendUserCredentialsEmail sends welcome email with login credentials to newly created user
func (e *EmailService) SendUserCredentialsEmail(toEmail, firstName, username, password, organizationName string) error {
	FrontendURL := e.config.FrontendURL
	brand := e.brandName()
	subject := fmt.Sprintf("Your %s Account - Login Credentials", brand)
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .credentials { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border: 2px solid #667eea; }
        .credential-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
        .credential-label { font-weight: bold; color: #667eea; }
        .credential-value { font-family: 'Courier New', monospace; color: #333; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to %s!</h1>
            <p>Secure SSH Access Made Simple</p>
        </div>
        <div class="content">
            <h2>Hello, %s!</h2>
            <p>Your account has been successfully created for <strong>%s</strong>. An administrator has set up your account and provided you with the following credentials:</p>

            <div class="credentials">
                <h3 style="margin-top: 0; color: #667eea;">🔑 Your Login Credentials</h3>
                <div class="credential-row">
                    <span class="credential-label">Email:</span>
                    <span class="credential-value">%s</span>
                </div>
                <div class="credential-row" style="border-bottom: none;">
                    <span class="credential-label">Password:</span>
                    <span class="credential-value">%s</span>
                </div>
            </div>

            <div class="warning">
                <strong>⚠️ Important Security Notice:</strong><br>
                Please change your password immediately after your first login. Keep your credentials safe and never share them with anyone.
            </div>

            <p>You can now log in to your account and start managing your infrastructure:</p>

            <p style="text-align: center; margin-top: 30px;">
                <a href="%s/login" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                    Log In Now
                </a>
            </p>

            <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0;">🚀 What you can do:</h3>
                <ul style="margin: 10px 0;">
                    <li>Manage SSH Machines securely</li>
                    <li>Connect to your servers through our terminal</li>
                    <li>Collaborate with your team</li>
                    <li>Monitor your infrastructure</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p>© 2026 %s. All rights reserved.</p>
            <p>Need help? Contact us at </p>
        </div>
    </div>
</body>
</html>
`, brand, firstName, organizationName, toEmail, password, FrontendURL, brand)

	return e.sendEmail(toEmail, subject, body)
}

// sendEmail sends an email using SMTP
func (e *EmailService) sendEmail(to, subject, htmlBody string) error {
	smtpHost, smtpPort, smtpUsername, password, from := e.smtpSettings()

	// Message
	message := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", from, to, subject, htmlBody))

	// Authentication
	auth := smtp.PlainAuth("", smtpUsername, password, smtpHost)

	// Send email
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	err := smtp.SendMail(addr, auth, from, []string{to}, message)
	if err != nil {
		e.logger.Error("Failed to send email",
			zap.String("to", to),
			zap.String("subject", subject),
			zap.Error(err))
		return fmt.Errorf("failed to send email: %w", err)
	}

	e.logger.Info("Email sent successfully",
		zap.String("to", to),
		zap.String("subject", subject))
	return nil
}
