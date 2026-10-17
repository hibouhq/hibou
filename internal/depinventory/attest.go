package depinventory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// In-toto attestations of SBOMs (ADR-046 §5): a DSSE envelope signs a
// statement whose predicate is a CycloneDX or SPDX document and whose
// subject names the deliverable by digest. Verification needs the public
// key the user trusts; keyless (Fulcio and Rekor) verification needs the
// Sigstore trust root and is not done here.

// Statement is an in-toto statement, v0.1 or v1.
type Statement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []Subject       `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject is what the statement is about: a file or an image, by digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// IsAttestation says whether data is a DSSE envelope or a bare statement.
func IsAttestation(data []byte) bool {
	var probe struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Type        string `json:"_type"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return false
	}
	return (probe.PayloadType != "" && probe.Payload != "") || strings.Contains(probe.Type, "in-toto.io/Statement")
}

// ParseAttestation reads a DSSE envelope (the envelope is returned with
// the statement it carries) or a bare statement (nil envelope).
func ParseAttestation(data []byte) (*Statement, *Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.PayloadType != "" && envelope.Payload != "" {
		payload, err := decodeBase64(envelope.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("envelope payload: %w", err)
		}
		var statement Statement
		if err := json.Unmarshal(payload, &statement); err != nil {
			return nil, nil, fmt.Errorf("envelope payload is not an in-toto statement: %w", err)
		}
		return &statement, &envelope, nil
	}
	var statement Statement
	if err := json.Unmarshal(data, &statement); err != nil {
		return nil, nil, fmt.Errorf("decode statement: %w", err)
	}
	if !strings.Contains(statement.Type, "in-toto.io/Statement") {
		return nil, nil, errors.New("not an in-toto statement")
	}
	return &statement, nil, nil
}

// SBOM returns the predicate as an SBOM document with its format when the
// predicate type is CycloneDX or SPDX, or when the predicate itself is
// one of the two.
func (s *Statement) SBOM() ([]byte, string, error) {
	if s == nil || len(s.Predicate) == 0 {
		return nil, "", errors.New("the statement has no predicate")
	}
	format := sbomFormat(s.Predicate)
	if format == "" {
		switch {
		case strings.Contains(s.PredicateType, "cyclonedx.org"):
			format = "cyclonedx"
		case strings.Contains(s.PredicateType, "spdx.dev"):
			format = "spdx"
		default:
			return nil, "", fmt.Errorf("predicate type %q is not an SBOM", s.PredicateType)
		}
	}
	return s.Predicate, format, nil
}

// SubjectSHA256 lists the sha256 digests the statement names.
func (s *Statement) SubjectSHA256() []string {
	var out []string
	for _, subject := range s.Subject {
		if digest := strings.ToLower(strings.TrimSpace(subject.Digest["sha256"])); digest != "" {
			out = append(out, digest)
		}
	}
	return out
}

// VerifyEnvelope checks the envelope's signatures against a PEM-encoded
// public key (PKIX: ECDSA with SHA-256, Ed25519, or RSA PKCS#1 v1.5 and
// PSS with SHA-256). One valid signature is enough, as DSSE specifies;
// the error names what was tried when none is.
func VerifyEnvelope(envelope *Envelope, pemKey []byte) error {
	if envelope == nil {
		return errors.New("no envelope")
	}
	if len(envelope.Signatures) == 0 {
		return errors.New("the envelope carries no signature")
	}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return errors.New("the key is not PEM-encoded")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	payload, err := decodeBase64(envelope.Payload)
	if err != nil {
		return fmt.Errorf("envelope payload: %w", err)
	}
	message := pae(envelope.PayloadType, payload)
	digest := sha256.Sum256(message)
	var last error
	for _, signature := range envelope.Signatures {
		sig, err := decodeBase64(signature.Sig)
		if err != nil {
			last = fmt.Errorf("signature %q: %w", signature.KeyID, err)
			continue
		}
		switch key := public.(type) {
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(key, digest[:], sig) {
				return nil
			}
		case ed25519.PublicKey:
			if ed25519.Verify(key, message, sig) {
				return nil
			}
		case *rsa.PublicKey:
			if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil || rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, nil) == nil {
				return nil
			}
		default:
			return fmt.Errorf("unsupported key type %T", public)
		}
		last = errors.New("no signature matches the key")
	}
	return last
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	var b strings.Builder
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteString(" ")
	b.WriteString(payloadType)
	b.WriteString(" ")
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteString(" ")
	b.Write(payload)
	return []byte(b.String())
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if out, err := base64.StdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	if out, err := base64.URLEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	return base64.RawURLEncoding.DecodeString(value)
}
