package depinventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testTime() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }

func pemPublic(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func envelopeJSON(t *testing.T, payload []byte, sign func([]byte) []byte) []byte {
	t.Helper()
	message := pae(mediaTypeInToto, payload)
	env, err := json.Marshal(Envelope{PayloadType: mediaTypeInToto, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []Signature{{KeyID: "k1", Sig: base64.StdEncoding.EncodeToString(sign(message))}}})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestParseAndVerifyAttestation(t *testing.T) {
	statement := statementJSON("https://cyclonedx.org/bom", cycloneDXDoc("pkg:npm/lodash@4.17.21"), strings.Repeat("ab", 32))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecEnvelope := envelopeJSON(t, statement, func(message []byte) []byte {
		digest := sha256.Sum256(message)
		sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	})
	if !IsAttestation(ecEnvelope) || !IsAttestation(statement) || IsAttestation(cycloneDXDoc("pkg:npm/a@1.0.0")) {
		t.Fatal("IsAttestation")
	}
	parsed, envelope, err := ParseAttestation(ecEnvelope)
	if err != nil || envelope == nil || parsed.PredicateType != "https://cyclonedx.org/bom" {
		t.Fatalf("parse envelope: %v %+v", err, parsed)
	}
	document, format, err := parsed.SBOM()
	if err != nil || format != "cyclonedx" || !strings.Contains(string(document), "lodash") {
		t.Fatalf("SBOM(): %v %s", err, format)
	}
	if got := parsed.SubjectSHA256(); len(got) != 1 || got[0] != strings.Repeat("ab", 32) {
		t.Errorf("subjects %v", got)
	}
	if err := VerifyEnvelope(envelope, pemPublic(t, &ecKey.PublicKey)); err != nil {
		t.Errorf("ecdsa verify: %v", err)
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyEnvelope(envelope, pemPublic(t, &otherKey.PublicKey)); err == nil {
		t.Error("a different key must not verify")
	}
	// A tampered payload fails.
	tampered := *envelope
	tampered.Payload = base64.StdEncoding.EncodeToString(statementJSON("https://cyclonedx.org/bom", cycloneDXDoc("pkg:npm/lodash@4.17.20"), strings.Repeat("ab", 32)))
	if err := VerifyEnvelope(&tampered, pemPublic(t, &ecKey.PublicKey)); err == nil {
		t.Error("a tampered payload must not verify")
	}

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edEnvelope := envelopeJSON(t, statement, func(message []byte) []byte { return ed25519.Sign(edPrivate, message) })
	_, envelope, err = ParseAttestation(edEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(envelope, pemPublic(t, edPublic)); err != nil {
		t.Errorf("ed25519 verify: %v", err)
	}

	// A bare statement parses without an envelope.
	bare, envelope, err := ParseAttestation(statement)
	if err != nil || envelope != nil || len(bare.Subject) != 1 {
		t.Errorf("bare statement: %v %+v", err, envelope)
	}
	if err := VerifyEnvelope(nil, nil); err == nil {
		t.Error("nil envelope must fail")
	}
}
