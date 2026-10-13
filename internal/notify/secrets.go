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

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
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
//
// enc:v2 values are bound (GCM additional data) to their organization, table,
// row and field, so a ciphertext copied into another row, org or field does
// not open. enc:v1 values (field-only binding) stay readable and are re-sealed
// as v2 on the row's next update.

// MaskedSecret replaces every non-empty secret field in API responses.
const MaskedSecret = "***"

// EncryptionKeyEnv names the instance key for config-secret encryption.
const EncryptionKeyEnv = "HIBOU_ENCRYPTION_KEY"

const (
	// sealedPrefix is what the server writes today (context-bound AAD).
	sealedPrefix = "enc:v2:"
	// sealedPrefixV1 values were bound to the field name only; read-only.
	sealedPrefixV1 = "enc:v1:"
)

// isSealedValue reports whether a value carries any server sealing prefix.
func isSealedValue(value string) bool {
	return strings.HasPrefix(value, sealedPrefix) || strings.HasPrefix(value, sealedPrefixV1)
}

// Tables a SealContext can name.
const (
	SealTableIntegrations      = "integrations"
	SealTableNotificationRules = "notification_rules"
)

// SealContext is what a sealed value is bound to besides its field: the row
// that owns it. A value sealed for one row does not open in another.
type SealContext struct {
	OrgID uuid.UUID
	Table string
	RowID uuid.UUID
}

// IntegrationSealContext binds values to an integration row.
func IntegrationSealContext(integration dbgen.Integration) SealContext {
	return SealContext{OrgID: integration.OrgID, Table: SealTableIntegrations, RowID: integration.ID}
}

// NotificationRuleSealContext binds values to a notification-rule row.
func NotificationRuleSealContext(rule dbgen.NotificationRule) SealContext {
	return SealContext{OrgID: rule.OrgID, Table: SealTableNotificationRules, RowID: rule.ID}
}

// errIncompleteSealContext refuses to seal without a full binding: a value
// sealed for "no row" could be replayed into any row.
var errIncompleteSealContext = errors.New("sealing a config secret requires its org, table and row id")

func (sc SealContext) complete() bool {
	return sc.OrgID != uuid.Nil && sc.RowID != uuid.Nil && sc.Table != ""
}

// aad is the v2 additional data: every part is fixed-width or NUL-free, and
// NUL-separated, so two different contexts never produce the same bytes.
func (sc SealContext) aad(field string) []byte {
	return []byte("hibou/config-secret/v2\x00" + sc.OrgID.String() + "\x00" + sc.Table + "\x00" + sc.RowID.String() + "\x00" + field)
}

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

func (c *SecretCodec) seal(sc SealContext, field, value string) (string, error) {
	if !c.Encrypts() || value == "" || isSealedValue(value) {
		return value, nil
	}
	if !sc.complete() {
		return "", errIncompleteSealContext
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(value), sc.aad(field))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *SecretCodec) open(sc SealContext, field, value string) (string, error) {
	var prefix string
	var aad []byte
	switch {
	case strings.HasPrefix(value, sealedPrefix):
		prefix, aad = sealedPrefix, sc.aad(field)
	case strings.HasPrefix(value, sealedPrefixV1):
		prefix, aad = sealedPrefixV1, []byte(field)
	default:
		return value, nil
	}
	if !c.Encrypts() {
		return "", ErrSealedWithoutKey
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", ErrSealedWithoutKey
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", ErrSealedWithoutKey
	}
	return string(plain), nil
}

// SealConfig encrypts every plaintext secret field, bound to sc. Without a
// key it returns the config unchanged. Already-sealed values are left as
// they are: open the config first to re-seal them (see MergeConfig).
func (c *SecretCodec) SealConfig(sc SealContext, raw json.RawMessage) (json.RawMessage, error) {
	return c.transform(raw, func(field, value string) (string, error) { return c.seal(sc, field, value) })
}

// OpenConfig decrypts every sealed secret field (v2 bound to sc, or legacy
// v1). Plaintext rows pass through.
func (c *SecretCodec) OpenConfig(sc SealContext, raw json.RawMessage) (json.RawMessage, error) {
	return c.transform(raw, func(field, value string) (string, error) { return c.open(sc, field, value) })
}

// ConfigHasSecrets reports whether a config holds a non-empty secret field.
func ConfigHasSecrets(raw json.RawMessage) bool {
	config, _ := decodeConfigObject(raw)
	for key, value := range config {
		if text, ok := value.(string); ok && text != "" && IsSecretConfigKey(key) {
			return true
		}
	}
	return false
}

// WithoutSecrets returns the config minus its secret fields.
func WithoutSecrets(raw json.RawMessage) json.RawMessage {
	config, ok := decodeConfigObject(raw)
	if !ok {
		return json.RawMessage("{}")
	}
	for key := range config {
		if IsSecretConfigKey(key) {
			delete(config, key)
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return json.RawMessage("{}")
	}
	return encoded
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

// destinationFields name, per integration type, the fields that decide where
// the stored credentials are sent. Changing one while keeping a stored secret
// would let an admin who cannot read the secret redirect it to a server they
// control, so MergeConfig then requires the secret to be re-entered.
var destinationFields = map[string][]string{
	"email":   {"smtp_host", "smtp_port", "smtp_username"},
	"webhook": {"url", "webhook_url"},
	"slack":   {"url", "webhook_url"},
	"teams":   {"url", "webhook_url"},
	"discord": {"url", "webhook_url"},
}

// allDestinationFields applies to an unknown type: every field any type uses.
var allDestinationFields = []string{"smtp_host", "smtp_port", "smtp_username", "url", "webhook_url"}

// DestinationFields lists the destination fields of an integration type.
func DestinationFields(kind string) []string {
	if fields, ok := destinationFields[strings.ToLower(strings.TrimSpace(kind))]; ok {
		return fields
	}
	return allDestinationFields
}

// ReenterSecretError refuses an update that changes where credentials go
// while keeping a stored secret (masked or omitted).
type ReenterSecretError struct {
	Field       string
	Destination string
}

func (e *ReenterSecretError) Error() string {
	return "re-enter " + e.Field + " when changing " + e.Destination
}

// MergeConfig applies an update to a stored config and returns the OPENED
// result: the caller seals it with SealConfig before storing, which also
// re-seals legacy v1 values under the row's v2 binding.
//
// A secret field that the update omits, or sends back as MaskedSecret, keeps
// its stored value; an explicit empty string or null clears it. Non-secret
// fields are taken from the update as sent. If a destination field of kind
// (DestinationFields) changes, every kept non-empty secret is refused with a
// *ReenterSecretError.
func (c *SecretCodec) MergeConfig(kind string, sc SealContext, stored, incoming json.RawMessage) (json.RawMessage, error) {
	next, ok := decodeConfigObject(incoming)
	if !ok {
		if len(bytes.TrimSpace(incoming)) == 0 {
			next = map[string]any{}
		} else {
			return nil, errors.New("config must be a JSON object")
		}
	}
	openedStored, err := c.OpenConfig(sc, stored)
	if err != nil {
		return nil, err
	}
	previous, _ := decodeConfigObject(openedStored)
	kept := map[string]bool{}
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
				kept[key] = true
			} else {
				delete(next, key)
			}
			continue
		}
		if isSealedValue(text) {
			return nil, ErrSealedValueSubmitted
		}
	}
	for key, value := range previous {
		if !IsSecretConfigKey(key) {
			continue
		}
		if _, sent := next[key]; !sent {
			next[key] = value
			kept[key] = true
		}
	}
	if err := checkDestinationChange(kind, previous, next, kept); err != nil {
		return nil, err
	}
	return json.Marshal(next)
}

func checkDestinationChange(kind string, previous, next map[string]any, kept map[string]bool) error {
	destinations := DestinationFields(kind)
	changed := ""
	for _, field := range destinations {
		if configScalar(previous[field]) != configScalar(next[field]) {
			changed = field
			break
		}
	}
	if changed == "" {
		return nil
	}
	isDestination := map[string]bool{}
	for _, field := range destinations {
		isDestination[field] = true
	}
	keptSecrets := make([]string, 0, len(kept))
	for key := range kept {
		if isDestination[key] {
			continue
		}
		if text, ok := next[key].(string); ok && text == "" {
			continue
		}
		if next[key] == nil {
			continue
		}
		keptSecrets = append(keptSecrets, key)
	}
	if len(keptSecrets) == 0 {
		return nil
	}
	sort.Strings(keptSecrets)
	return &ReenterSecretError{Field: keptSecrets[0], Destination: changed}
}

// configScalar renders a config value for equality checks: "587" and 587
// are the same port, a missing field and "" the same (absent) host.
func configScalar(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

// RuleSecretSelectorError refuses a notification-rule destination_config
// that names a credential field. Rule configs only select integrations; a
// rule matching on a secret would be an oracle for the integration's
// write-only credential (dry-run says whether a guess matched).
type RuleSecretSelectorError struct {
	Field string
}

func (e *RuleSecretSelectorError) Error() string {
	return "destination_config." + e.Field + " is a credential and cannot select integrations; remove it (select one integration with integration_id)"
}

// ValidateRuleDestinationConfig checks a notification rule's destination
// config: an object with no credential field at all (masked or not), and an
// integration_id, if any, given as a string.
func ValidateRuleDestinationConfig(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	config, ok := decodeConfigObject(raw)
	if !ok {
		return errors.New("destination_config must be a JSON object")
	}
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if IsSecretConfigKey(key) {
			return &RuleSecretSelectorError{Field: key}
		}
	}
	if value, ok := config[RuleIntegrationIDKey]; ok {
		if _, isString := value.(string); !isString {
			return errors.New("destination_config." + RuleIntegrationIDKey + " must be a string")
		}
	}
	return nil
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
		if isSealedValue(text) {
			return ErrSealedValueSubmitted
		}
	}
	return nil
}

// ChangedConfigFields lists the top-level config fields that differ between
// two configs, compared after opening, so the audit log can say WHAT changed
// without ever saying to what. Secret fields are reported by name only.
func (c *SecretCodec) ChangedConfigFields(sc SealContext, before, after json.RawMessage) []string {
	opened := func(raw json.RawMessage) map[string]any {
		if plain, err := c.OpenConfig(sc, raw); err == nil {
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
		// Every configured value, however short: a 3-character password is
		// still a password.
		if text, ok := value.(string); ok && text != "" && text != MaskedSecret {
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
