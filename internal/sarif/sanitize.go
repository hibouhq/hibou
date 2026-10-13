package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrDocumentTooLarge refuses a SARIF document over MaxDocumentSize.
var ErrDocumentTooLarge = fmt.Errorf("sarif document exceeds %d MB", MaxDocumentSize>>20)

// MaxDocumentSize is the largest SARIF document hibou parses or stores.
const MaxDocumentSize = maxDocumentSize

// maxSanitizeDepth bounds nesting; real SARIF stays far below it.
const maxSanitizeDepth = 256

// A stripped field is a property name, dropped wherever it appears inside an
// object whose owner — the key that holds the object, directly or through an
// array — is one of owners. An empty owner set matches any object.
type strippedField struct {
	owners map[string]bool
	// objectOnly drops the field only when its value is an object.
	objectOnly bool
}

// strippedFields are the places a SARIF log carries source or file content,
// which secret scanners fill with the matched secret verbatim and hibou never
// reads:
//   - region.snippet, contextRegion.snippet, deletedRegion.snippet (results,
//     related locations, code flows, stacks, fixes);
//   - artifacts[].contents (the whole file, as text or base64 binary);
//   - fixes[].artifactChanges[].replacements[].insertedContent;
//   - any artifactContent's "rendered" (multiformat rendering of the same).
var strippedFields = map[string]strippedField{
	"snippet":         {owners: map[string]bool{"region": true, "contextRegion": true, "deletedRegion": true}},
	"contents":        {owners: map[string]bool{"artifacts": true}},
	"insertedContent": {owners: map[string]bool{"replacements": true}},
	"rendered":        {objectOnly: true},
}

// StripSnippets removes the source and file content a SARIF log carries
// (strippedFields) and returns the re-encoded document.
//
// The document is always re-encoded from a token stream — never returned as
// received — so every occurrence of a duplicated key is filtered, and memory
// stays bounded by the largest single string rather than a full object tree.
// It must be one JSON object, with nothing after it, of at most
// MaxDocumentSize bytes. Numbers are preserved exactly; whitespace is not.
func StripSnippets(content []byte) ([]byte, error) {
	if len(content) > MaxDocumentSize {
		return nil, ErrDocumentTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}
	if delim, ok := first.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("decode sarif: document is not a JSON object")
	}
	s := &sanitizer{decoder: decoder}
	s.out.Grow(len(content))
	if err := s.copyValue(first, ""); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode sarif: unexpected data after the document")
	}
	return s.out.Bytes(), nil
}

type sanitizer struct {
	decoder *json.Decoder
	out     bytes.Buffer
	depth   int
}

// copyValue writes the value starting at token; owner is the key that holds
// it (inherited through arrays).
func (s *sanitizer) copyValue(token json.Token, owner string) error {
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return s.writeScalar(token)
	}
	s.depth++
	defer func() { s.depth-- }()
	if s.depth > maxSanitizeDepth {
		return errors.New("document nested too deeply")
	}
	switch delim {
	case '{':
		return s.copyObject(owner)
	case '[':
		return s.copyArray(owner)
	default:
		return fmt.Errorf("unexpected %q", delim)
	}
}

func (s *sanitizer) copyObject(owner string) error {
	s.out.WriteByte('{')
	first := true
	for {
		token, err := s.decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok && delim == '}' {
			s.out.WriteByte('}')
			return nil
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		value, err := s.decoder.Token()
		if err != nil {
			return err
		}
		if s.stripped(key, owner, value) {
			if err := s.skipValue(value); err != nil {
				return err
			}
			continue
		}
		if !first {
			s.out.WriteByte(',')
		}
		first = false
		if err := s.writeScalar(key); err != nil {
			return err
		}
		s.out.WriteByte(':')
		if err := s.copyValue(value, key); err != nil {
			return err
		}
	}
}

func (s *sanitizer) copyArray(owner string) error {
	s.out.WriteByte('[')
	first := true
	for {
		token, err := s.decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok && delim == ']' {
			s.out.WriteByte(']')
			return nil
		}
		if !first {
			s.out.WriteByte(',')
		}
		first = false
		if err := s.copyValue(token, owner); err != nil {
			return err
		}
	}
}

func (s *sanitizer) stripped(key, owner string, value json.Token) bool {
	field, ok := strippedFields[key]
	if !ok {
		return false
	}
	if len(field.owners) > 0 && !field.owners[owner] {
		return false
	}
	if field.objectOnly {
		delim, isDelim := value.(json.Delim)
		return isDelim && delim == '{'
	}
	return true
}

// skipValue consumes the rest of a value whose first token was already read,
// still checking its syntax (the decoder does).
func (s *sanitizer) skipValue(token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("unexpected %q", delim)
	}
	depth := 1
	for depth > 0 {
		next, err := s.decoder.Token()
		if err != nil {
			return err
		}
		if d, isDelim := next.(json.Delim); isDelim {
			switch d {
			case '{', '[':
				depth++
				if s.depth+depth > maxSanitizeDepth {
					return errors.New("document nested too deeply")
				}
			default:
				depth--
			}
		}
	}
	return nil
}

func (s *sanitizer) writeScalar(token json.Token) error {
	switch value := token.(type) {
	case nil:
		s.out.WriteString("null")
	case bool:
		if value {
			s.out.WriteString("true")
		} else {
			s.out.WriteString("false")
		}
	case json.Number:
		s.out.WriteString(value.String())
	case string:
		encoder := json.NewEncoder(&s.out)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			return err
		}
		s.out.Truncate(s.out.Len() - 1) // Encode appends '\n'
	default:
		return fmt.Errorf("unexpected token %T", token)
	}
	return nil
}
