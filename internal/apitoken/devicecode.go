package apitoken

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// Device authorization codes (RFC 8628, ADR-043). The device code is the
// client's polling secret; the user code is what a person reads off the
// terminal and types or confirms in the browser.

// userCodeAlphabet is RFC 8628 §6.1's example set: consonants only, so a code
// never spells a word and has no 0/O or 1/I look-alikes.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLength is the number of significant characters in a user code.
// 20^8 ≈ 2.6e10 codes against a 10-minute lifetime.
const UserCodeLength = 8

// GenerateDeviceCode returns a 256-bit random, URL-safe polling secret.
func GenerateDeviceCode() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateUserCode returns a normalised user code (UserCodeLength characters,
// no separator). Display it with FormatUserCode.
func GenerateUserCode() (string, error) {
	const maxUnbiased = 256 - (256 % len(userCodeAlphabet))
	out := make([]byte, UserCodeLength)
	buf := make([]byte, 1)
	for i := 0; i < UserCodeLength; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= maxUnbiased {
			continue
		}
		out[i] = userCodeAlphabet[int(buf[0])%len(userCodeAlphabet)]
		i++
	}
	return string(out), nil
}

// NormalizeUserCode turns what a person typed into the stored form: upper
// case, separators and spaces dropped. It returns false when the result is not
// a well-formed code, so a malformed lookup never reaches the database.
func NormalizeUserCode(input string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(input) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	code := b.String()
	return code, len(code) == UserCodeLength
}

// FormatUserCode renders a normalised code as XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != UserCodeLength {
		return code
	}
	return code[:UserCodeLength/2] + "-" + code[UserCodeLength/2:]
}
