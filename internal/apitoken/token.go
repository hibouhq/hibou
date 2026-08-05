package apitoken

import (
	"crypto/rand"
	"hash/crc32"
	"strings"
)

// Prefix identifies a Hibou personal access token. It is intentionally
// greppable so leaked tokens are detectable by secret scanners (ours included).
const Prefix = "hibou_pat_"

const (
	randomLen   = 30
	checksumLen = 6
	base62      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Generate returns a new raw token of the form hibou_pat_<random><checksum>.
// The caller stores only its hash; the raw value is shown to the user once.
func Generate() (string, error) {
	body, err := randomBase62(randomLen)
	if err != nil {
		return "", err
	}
	return Prefix + body + checksum(body), nil
}

// HasValidChecksum reports whether raw has the token shape and a matching
// checksum — a cheap structural check before any database lookup.
func HasValidChecksum(raw string) bool {
	rest, ok := strings.CutPrefix(strings.TrimSpace(raw), Prefix)
	if !ok || len(rest) != randomLen+checksumLen {
		return false
	}
	body, sum := rest[:randomLen], rest[randomLen:]
	return sum == checksum(body)
}

// LooksLike reports whether raw carries the token prefix, for secret-scanner
// detection where the checksum is not needed.
func LooksLike(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), Prefix)
}

func checksum(body string) string {
	return encodeBase62Fixed(uint64(crc32.ChecksumIEEE([]byte(body))), checksumLen)
}

func encodeBase62Fixed(value uint64, width int) string {
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = base62[value%62]
		value /= 62
	}
	return string(out)
}

func randomBase62(n int) (string, error) {
	const maxUnbiased = 256 - (256 % 62)
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= maxUnbiased {
			continue
		}
		out[i] = base62[int(buf[0])%62]
		i++
	}
	return string(out), nil
}
