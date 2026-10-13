package notify

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Integration and notification-rule configs are JSON objects whose credential
// fields (webhook URLs carry their token in the path, HMAC secrets, SMTP
// passwords) are write-only through the API: responses carry MaskedSecret in
// their place, and an update that sends the marker back — or omits the field
// — keeps the stored value.
//
// With HIBOU_ENCRYPTION_KEY set, those fields are also sealed at rest with
// AES-256-GCM under a versioned prefix. Rows written before the key was set
// stay readable (no prefix = plaintext), so turning encryption on is a
// forward-only, zero-migration change; existing rows are sealed on their next
// update.

// MaskedSecret replaces every non-empty secret field in API responses.
const MaskedSecret = "***"

// EncryptionKeyEnv names the instance key for config-secret encryption.
const EncryptionKeyEnv = "HIBOU_ENCRYPTION_KEY"

const sealedPrefix = "enc:v1:"

// secretConfigKeys are the config fields treated as credentials. A webhook
// URL is one: Slack/Teams/Discord URLs authenticate by their path alone.
var secretConfigKeys = map[string]bool{
	"secret":        true,
	"url":           true,
	"webhook_url":   true,
	"smtp_password": true,
	"password":      true,
	"token":         true,
	"api_key":       true,
}

// IsSecretConfigKey reports whether a config field is write-only.
func IsSecretConfigKey(key string) bool {
	return secretConfigKeys[strings.ToLower(strings.TrimSpace(key))]
}

// ErrSealedWithoutKey is returned when a sealed field is read on an instance
// that has no (or another) encryption key.
var ErrSealedWithoutKey = errors.New("integration config is encrypted but " + EncryptionKeyEnv + " is missing or does not match")

// SecretCodec seals and opens secret config fields. A codec without a key
// stores plaintext and fails to open sealed values.
type SecretCodec struct {
	aead cipher.AEAD
}

// NewSecretCodec builds a codec from a 32-byte key; an empty key yields a
// plaintext codec.
func NewSecretCodec(key []byte) (*SecretCodec, error) {
	if len(key) == 0 {
		return &SecretCodec{}, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", EncryptionKeyEnv, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretCodec{aead: aead}, nil
}

// ParseEncryptionKey decodes HIBOU_ENCRYPTION_KEY (standard or URL-safe
// base64, padded or not) into a 32-byte key. Empty input is no key.
func ParseEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := encoding.DecodeString(raw); err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("%s must decode to 32 bytes, got %d (generate one with `openssl rand -base64 32`)", EncryptionKeyEnv, len(key))
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("%s must be base64 (generate one with `openssl rand -base64 32`)", EncryptionKeyEnv)
}

var (
	codecMu      sync.RWMutex
	globalCodec  *SecretCodec
	codecFromEnv sync.Once
)

// SetEncryptionKey installs the instance key. Call it at startup with
// config.EncryptionKey; without a call the key is read from the environment.
func SetEncryptionKey(key []byte) error {
	codec, err := NewSecretCodec(key)
	if err != nil {
		return err
	}
	codecFromEnv.Do(func() {})
	codecMu.Lock()
	globalCodec = codec
	codecMu.Unlock()
	return nil
}

// Secrets returns the instance codec.
func Secrets() *SecretCodec {
	codecFromEnv.Do(func() {
		codec := &SecretCodec{}
		if key, err := ParseEncryptionKey(os.Getenv(EncryptionKeyEnv)); err == nil && len(key) > 0 {
			if built, buildErr := NewSecretCodec(key); buildErr == nil {
				codec = built
			}
		}
		codecMu.Lock()
		if globalCodec == nil {
			globalCodec = codec
		}
		codecMu.Unlock()
	})
	codecMu.RLock()
	defer codecMu.RUnlock()
	if globalCodec == nil {
		return &SecretCodec{}
	}
	return globalCodec
}

// Encrypts reports whether the codec seals at rest.
func (c *SecretCodec) Encrypts() bool { return c != nil && c.aead != nil }

func (c *SecretCodec) seal(field, value string) (string, error) {
	if !c.Encrypts() || value == "" || strings.HasPrefix(value, sealedPrefix) {
		return value, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(value), []byte(field))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *SecretCodec) open(field, value string) (string, error) {
	if !strings.HasPrefix(value, sealedPrefix) {
		return value, nil
	}
	if !c.Encrypts() {
		return "", ErrSealedWithoutKey
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, sealedPrefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", ErrSealedWithoutKey
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ciphertext, []byte(field))
	if err != nil {
		return "", ErrSealedWithoutKey
	}
	return string(plain), nil
}

// SealConfig encrypts every plaintext secret field. Without a key it returns
// the config unchanged.
func (c *SecretCodec) SealConfig(raw json.RawMessage) (json.RawMessage, error) {
	return c.transform(raw, c.seal)
}

// OpenConfig decrypts every sealed secret field. Plaintext rows pass through.
func (c *SecretCodec) OpenConfig(raw json.RawMessage) (json.RawMessage, error) {
	return c.transform(raw, c.open)
}

func (c *SecretCodec) transform(raw json.RawMessage, apply func(field, value string) (string, error)) (json.RawMessage, error) {
	config, ok := decodeConfigObject(raw)
	if !ok {
		return raw, nil
	}
	changed := false
	for key, value := range config {
		text, isString := value.(string)
		if !isString || !IsSecretConfigKey(key) {
			continue
		}
		out, err := apply(key, text)
		if err != nil {
			return nil, err
		}
		if out != text {
			config[key] = out
			changed = true
		}
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(config)
}

// MaskConfig replaces every non-empty secret field with MaskedSecret. A
// config that is not a JSON object is replaced by an empty object: it cannot
// be inspected, so it cannot be shown.
func MaskConfig(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("{}")
	}
	config, ok := decodeConfigObject(raw)
	if !ok {
		return json.RawMessage("{}")
	}
	for key, value := range config {
		if !IsSecretConfigKey(key) || value == nil {
			continue
		}
		if text, isString := value.(string); isString && text == "" {
			continue
		}
		config[key] = MaskedSecret
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return json.RawMessage("{}")
	}
	return encoded
}

// ErrSealedValueSubmitted refuses a client-supplied value that looks sealed:
// only the server writes that prefix.
var ErrSealedValueSubmitted = errors.New("config secret values must not start with the server's sealed-value prefix")

// MergeConfig applies an update to a stored config. A secret field that the
// update omits, or sends back as MaskedSecret, keeps its stored value; an
// explicit empty string or null clears it. Non-secret fields are taken from
// the update as sent.
func MergeConfig(stored, incoming json.RawMessage) (json.RawMessage, error) {
	next, ok := decodeConfigObject(incoming)
	if !ok {
		if len(bytes.TrimSpace(incoming)) == 0 {
			next = map[string]any{}
		} else {
			return nil, errors.New("config must be a JSON object")
		}
	}
	previous, _ := decodeConfigObject(stored)
	for key, value := range next {
		if !IsSecretConfigKey(key) {
			continue
		}
		text, isString := value.(string)
		if !isString {
			continue
		}
		if text == MaskedSecret {
			if old, had := previous[key]; had {
				next[key] = old
			} else {
				delete(next, key)
			}
			continue
		}
		if strings.HasPrefix(text, sealedPrefix) {
			return nil, ErrSealedValueSubmitted
		}
	}
	for key, value := range previous {
		if !IsSecretConfigKey(key) {
			continue
		}
		if _, sent := next[key]; !sent {
			next[key] = value
		}
	}
	return json.Marshal(next)
}

// ValidateNewConfig checks a create payload: it must be an object and carry
// no masked marker or sealed value (there is nothing stored to keep).
func ValidateNewConfig(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	config, ok := decodeConfigObject(raw)
	if !ok {
		return errors.New("config must be a JSON object")
	}
	for key, value := range config {
		text, isString := value.(string)
		if !isString || !IsSecretConfigKey(key) {
			continue
		}
		if text == MaskedSecret {
			return fmt.Errorf("config.%s: %q is the masked marker, not a value", key, MaskedSecret)
		}
		if strings.HasPrefix(text, sealedPrefix) {
			return ErrSealedValueSubmitted
		}
	}
	return nil
}

// ChangedConfigFields lists the top-level config fields that differ between
// two configs, compared after opening, so the audit log can say WHAT changed
// without ever saying to what. Secret fields are reported by name only.
func (c *SecretCodec) ChangedConfigFields(before, after json.RawMessage) []string {
	opened := func(raw json.RawMessage) map[string]any {
		if plain, err := c.OpenConfig(raw); err == nil {
			raw = plain
		}
		config, _ := decodeConfigObject(raw)
		if config == nil {
			config = map[string]any{}
		}
		return config
	}
	left, right := opened(before), opened(after)
	fields := make([]string, 0)
	for key, value := range right {
		if !valuesEqual(value, left[key]) {
			fields = append(fields, key)
		}
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

// ConfigKeys lists a config's top-level field names, sorted.
func ConfigKeys(raw json.RawMessage) []string {
	config, _ := decodeConfigObject(raw)
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// secretValues returns the opened secret strings of a config, for scrubbing
// them out of error text.
func secretValues(config map[string]any) []string {
	values := make([]string, 0, 4)
	for key, value := range config {
		if !IsSecretConfigKey(key) {
			continue
		}
		if text, ok := value.(string); ok && len(text) >= 4 && text != MaskedSecret {
			values = append(values, text)
		}
	}
	return values
}

func decodeConfigObject(raw json.RawMessage) (map[string]any, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil || config == nil {
		return nil, false
	}
	return config, true
}
