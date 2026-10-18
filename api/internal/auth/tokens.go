package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
)

// NewToken returns a URL-safe random token with n bytes of entropy.
func NewToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns SHA-256 of a high-entropy token. Suitable only for random
// tokens (sessions, email tokens). Never use for passwords.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randomBase62(n int) (string, error) {
	var sb strings.Builder
	max := big.NewInt(int64(len(base62)))
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(base62[v.Int64()])
	}
	return sb.String(), nil
}

// APIKey is a freshly generated API key. Plaintext is shown to the user once.
type APIKey struct {
	Prefix    string // public identifier, stored in clear
	Plaintext string // rb_live_<prefix>_<secret>
	Verifier  []byte // HMAC-SHA256(pepper, secret)
}

const APIKeyScheme = "rb_live_"

func NewAPIKey(pepper []byte) (APIKey, error) {
	prefix, err := randomBase62(10)
	if err != nil {
		return APIKey{}, err
	}
	secret, err := randomBase62(43) // ~256 bits
	if err != nil {
		return APIKey{}, err
	}
	return APIKey{
		Prefix:    prefix,
		Plaintext: APIKeyScheme + prefix + "_" + secret,
		Verifier:  APIKeyVerifier(pepper, secret),
	}, nil
}

func APIKeyVerifier(pepper []byte, secret string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(secret))
	return m.Sum(nil)
}

var ErrMalformedAPIKey = errors.New("malformed api key")

// ParseAPIKey splits a presented key into prefix and secret.
func ParseAPIKey(s string) (prefix, secret string, err error) {
	rest, ok := strings.CutPrefix(s, APIKeyScheme)
	if !ok {
		return "", "", ErrMalformedAPIKey
	}
	prefix, secret, ok = strings.Cut(rest, "_")
	if !ok || len(prefix) != 10 || len(secret) != 43 {
		return "", "", ErrMalformedAPIKey
	}
	return prefix, secret, nil
}

// Sealer encrypts small secrets (e.g. TOTP seeds) with AES-256-GCM.
type Sealer struct{ aead cipher.AEAD }

func NewSealer(key []byte) (*Sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (s *Sealer) Open(ciphertext, aad []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
}
