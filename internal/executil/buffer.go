// Package executil contains small, shared subprocess primitives. Callers own
// executable selection, execution permissions and domain-specific validation.
package executil

import (
	"bytes"
	"errors"
)

var ErrOutputLimit = errors.New("command output exceeds the configured limit")

// Buffer does not embed bytes.Buffer: promoted ReadFrom/WriteString methods
// would let io.Copy bypass the output limit.
type Buffer struct {
	data    bytes.Buffer
	limit   int
	failure error
}

func NewBuffer(limit int) *Buffer { return &Buffer{limit: limit} }

func (b *Buffer) Write(p []byte) (int, error) {
	if b.limit < 0 || len(p) > b.limit-b.data.Len() {
		b.failure = ErrOutputLimit
		return 0, ErrOutputLimit
	}
	return b.data.Write(p)
}

func (b *Buffer) Bytes() []byte { return b.data.Bytes() }
func (b *Buffer) Len() int      { return b.data.Len() }
func (b *Buffer) Err() error    { return b.failure }
