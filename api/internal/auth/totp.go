package auth

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const TOTPIssuer = "ReverseBug"

// NewTOTP generates a TOTP key for the account.
func NewTOTP(account string) (secret, url string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: TOTPIssuer, AccountName: account})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

// ValidateTOTP accepts the current code with ±1 step skew.
// Replay protection is enforced by the caller (one-time use per code window).
func ValidateTOTP(code, secret string, now time.Time) bool {
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}
