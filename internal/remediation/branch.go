package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"

	"github.com/hibouhq/hibou/internal/forge"
)

// BranchName uses exactly one slash while keeping differently named targets distinct.
func BranchName(target, baseSHA, artifactSHA256 string) (string, error) {
	if strings.TrimSpace(target) == "" || !validSHA(baseSHA) {
		return "", errors.New("remediation branch requires a target and full base commit SHA")
	}
	digest, err := hex.DecodeString(artifactSHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", errors.New("remediation branch requires a SHA-256 artifact digest")
	}
	var slug strings.Builder
	for _, c := range target {
		if c < unicode.MaxASCII && (unicode.IsLetter(c) || unicode.IsDigit(c)) {
			slug.WriteRune(unicode.ToLower(c))
		} else if slug.Len() > 0 && !strings.HasSuffix(slug.String(), "-") {
			slug.WriteByte('-')
		}
		if slug.Len() >= 48 {
			break
		}
	}
	name := strings.Trim(slug.String(), "-")
	if name == "" {
		name = "target"
	}
	sum := sha256.Sum256([]byte(target + "\x00" + strings.ToLower(baseSHA) + "\x00" + strings.ToLower(artifactSHA256)))
	branch := "hibou/fix-" + name + "-" + hex.EncodeToString(sum[:8])
	if err := forge.CheckWriteBranch(branch); err != nil {
		return "", err
	}
	return branch, nil
}

func validSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
