// Package auth contains credential primitives built on maintained libraries:
// Argon2id (golang.org/x/crypto), crypto/rand tokens, AES-GCM, and TOTP (pquerna/otp).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters follow the OWASP Password Storage Cheat Sheet
// (m=19 MiB, t=2, p=1 minimum). We use m=64 MiB, t=3, p=2.
type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

var ErrInvalidHash = errors.New("invalid password hash format")

const (
	MinPasswordLen = 12
	MaxPasswordLen = 256 // bounds hashing cost (DoS protection)
)

// ValidatePasswordPolicy follows NIST SP 800-63B: length-based, no composition rules.
func ValidatePasswordPolicy(pw, email string) error {
	n := len([]rune(pw))
	if n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	}
	lower := strings.ToLower(pw)
	if local, _, ok := strings.Cut(strings.ToLower(email), "@"); ok && len(local) >= 4 && strings.Contains(lower, local) {
		return errors.New("password must not contain your email address")
	}
	for _, common := range commonPasswords {
		if lower == common {
			return errors.New("password is too common")
		}
	}
	return nil
}

var commonPasswords = []string{
	"password1234", "123456789012", "qwertyuiopas", "passwordpassword", "reversebug123",
	"iloveyou1234", "adminadmin123", "letmein12345", "welcome12345", "changeme1234",
}

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword compares in constant time. needsRehash reports whether the
// stored hash uses weaker parameters than `current`.
func VerifyPassword(pw, encoded string, current Argon2Params) (ok bool, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, ErrInvalidHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return false, false, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, false, ErrInvalidHash
	}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	needsRehash = p.Memory < current.Memory || p.Time < current.Time || p.Threads < current.Threads
	return ok, needsRehash, nil
}

// dummyHash is verified against when a user does not exist so that login
// timing does not reveal account existence.
var dummyHash, _ = HashPassword("reversebug-timing-equalizer", DefaultArgon2)

func EqualizeTiming(pw string) { _, _, _ = VerifyPassword(pw, dummyHash, DefaultArgon2) }
