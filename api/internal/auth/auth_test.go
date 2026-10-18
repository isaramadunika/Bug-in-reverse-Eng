package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

var fastParams = Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple", fastParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected format %q", h)
	}
	ok, _, err := VerifyPassword("correct horse battery staple", h, fastParams)
	if err != nil || !ok {
		t.Fatalf("expected match, ok=%v err=%v", ok, err)
	}
	ok, _, _ = VerifyPassword("wrong password here", h, fastParams)
	if ok {
		t.Fatal("expected mismatch")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same password value", fastParams)
	b, _ := HashPassword("same password value", fastParams)
	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestNeedsRehash(t *testing.T) {
	h, _ := HashPassword("some long password", fastParams)
	_, rehash, _ := VerifyPassword("some long password", h, DefaultArgon2)
	if !rehash {
		t.Fatal("weaker params should require rehash")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$garbage$AA$AA"} {
		if _, _, err := VerifyPassword("x", bad, fastParams); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := map[string]bool{
		"short":                    false,
		"password1234":             false,
		"alice-secret-phrase-99":   false, // contains email local part
		"a perfectly fine passphrase": true,
		strings.Repeat("x", 300):   false,
	}
	for pw, want := range cases {
		err := ValidatePasswordPolicy(pw, "alice@example.com")
		if (err == nil) != want {
			t.Errorf("policy(%q) err=%v want ok=%v", pw, err, want)
		}
	}
}

func TestTokensUniqueAndHashed(t *testing.T) {
	a, _ := NewToken(32)
	b, _ := NewToken(32)
	if a == b || len(a) < 40 {
		t.Fatalf("weak tokens %q %q", a, b)
	}
	if string(HashToken(a)) == a || len(HashToken(a)) != 32 {
		t.Fatal("hash must be 32-byte digest")
	}
}

func TestAPIKeyRoundTrip(t *testing.T) {
	pepper := []byte("0123456789abcdef0123456789abcdef")
	k, err := NewAPIKey(pepper)
	if err != nil {
		t.Fatal(err)
	}
	prefix, secret, err := ParseAPIKey(k.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != k.Prefix {
		t.Fatal("prefix mismatch")
	}
	if string(APIKeyVerifier(pepper, secret)) != string(k.Verifier) {
		t.Fatal("verifier mismatch")
	}
	if strings.Contains(string(k.Verifier), secret) {
		t.Fatal("verifier must not contain secret")
	}
	for _, bad := range []string{"", "rb_live_", "rb_test_abc_def", k.Plaintext + "x", "rb_live_short_secret"} {
		if _, _, err := ParseAPIKey(bad); err == nil {
			t.Errorf("expected parse error for %q", bad)
		}
	}
}

func TestSealer(t *testing.T) {
	s, err := NewSealer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := s.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user-1"))
	pt, err := s.Open(ct, []byte("user-1"))
	if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := s.Open(ct, []byte("user-2")); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
}

func TestTOTP(t *testing.T) {
	secret, url, err := NewTOTP("alice@example.com")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/") {
		t.Fatalf("generate: %v %q", err, url)
	}
	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)
	if !ValidateTOTP(code, secret, now) {
		t.Fatal("valid code rejected")
	}
	if ValidateTOTP(code, secret, now.Add(5*time.Minute)) {
		t.Fatal("stale code accepted")
	}
}
