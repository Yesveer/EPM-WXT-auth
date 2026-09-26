package services

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

const (
	OTPLength      = 6
	MaxOTPAttempts = 3
)

// OTPService handles OTP generation and validation using MongoDB
type OTPService struct {
	store  *database.Store
	config *config.Config
	logger *zap.Logger
}

func NewOTPService(store *database.Store, cfg *config.Config, logger *zap.Logger) *OTPService {
	return &OTPService{
		store:  store,
		config: cfg,
		logger: logger,
	}
}

// GenerateOTP generates a 6-digit OTP and stores it in MongoDB
func (o *OTPService) GenerateOTP(username, tenantID string) (string, error) {
	// Generate random 6-digit code
	code, err := o.generateNumericCode(OTPLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(time.Duration(o.GetOTPExpiryMinutes()) * time.Minute)

	// Create OTP session
	session := &database.OTPSession{
		Username:  username,
		OTPCode:   code,
		TenantID:  tenantID,
		Attempts:  0,
		ExpiresAt: expiresAt,
	}

	if err := o.store.CreateOTPSession(session); err != nil {
		return "", fmt.Errorf("failed to store OTP: %w", err)
	}

	o.logger.Info("OTP generated",
		zap.String("username", username),
		zap.Time("expires_at", expiresAt))

	return code, nil
}

// ValidateOTP validates an OTP code
func (o *OTPService) ValidateOTP(username, code string) (bool, error) {
	// Get OTP session
	session, err := o.store.GetOTPSession(username)
	if err != nil {
		o.logger.Warn("OTP session not found",
			zap.String("username", username),
			zap.Error(err))
		return false, fmt.Errorf("OTP not found or expired")
	}

	// Check if too many attempts
	if session.Attempts >= MaxOTPAttempts {
		o.logger.Warn("OTP max attempts exceeded",
			zap.String("username", username),
			zap.Int("attempts", session.Attempts))
		// Delete the session
		_ = o.store.DeleteOTPSession(username)
		return false, fmt.Errorf("maximum OTP attempts exceeded")
	}

	// Check if OTP matches
	if session.OTPCode != code {
		// Increment attempts
		if err := o.store.IncrementOTPAttempts(username); err != nil {
			o.logger.Error("Failed to increment OTP attempts", zap.Error(err))
		}

		o.logger.Warn("Invalid OTP",
			zap.String("username", username),
			zap.Int("attempts", session.Attempts+1))
		return false, fmt.Errorf("invalid OTP code")
	}

	// Valid OTP - delete the session
	if err := o.store.DeleteOTPSession(username); err != nil {
		o.logger.Error("Failed to delete OTP session", zap.Error(err))
	}

	o.logger.Info("OTP validated successfully", zap.String("username", username))
	return true, nil
}

// DeleteOTP deletes an OTP session
func (o *OTPService) DeleteOTP(username, tenantID string) error {
	return o.store.DeleteOTPSession(username)
}

// GetOTPExpiryMinutes returns the OTP expiry time in minutes — the super_admin
// configured value from the database, falling back to the env-loaded default
// if it was never customized.
func (o *OTPService) GetOTPExpiryMinutes() int {
	settings, err := o.store.GetMFASettings()
	if err != nil || settings == nil || settings.OTPExpiryMinutes <= 0 {
		return o.config.OTPExpiryMinutes
	}
	return settings.OTPExpiryMinutes
}

// IsEnabled reports whether OTP/email-2FA is currently on — the super_admin
// configured value from the database, falling back to the env-loaded default
// if it was never customized via the UI.
func (o *OTPService) IsEnabled() bool {
	settings, err := o.store.GetMFASettings()
	if err != nil || settings == nil {
		return o.config.OTPEnabled
	}
	return settings.OTPEnabled
}

// CleanupExpiredOTPs removes expired OTP sessions (MongoDB TTL handles this automatically)
func (o *OTPService) CleanupExpiredOTPs() {
	// MongoDB TTL index automatically removes expired documents
	// This method is kept for potential manual cleanup if needed
	o.logger.Debug("OTP cleanup triggered (handled by MongoDB TTL)")
}

// generateNumericCode generates a random numeric code of specified length
func (o *OTPService) generateNumericCode(length int) (string, error) {
	const digits = "0123456789"
	code := make([]byte, length)

	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[num.Int64()]
	}

	return string(code), nil
}
