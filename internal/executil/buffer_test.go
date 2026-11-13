package executil

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBufferBoundsWritesAndCopy(t *testing.T) {
	if _, ok := any(NewBuffer(3)).(io.ReaderFrom); ok {
		t.Fatal("ReaderFrom would bypass bounded writes")
	}
	for _, copy := range []bool{false, true} {
		b := NewBuffer(3)
		var err error
		if copy {
			_, err = io.Copy(b, strings.NewReader("four"))
		} else {
			_, err = b.Write([]byte("four"))
		}
		if !errors.Is(err, ErrOutputLimit) || b.Len() != 0 {
			t.Fatalf("limit bypassed: %q %v", b.Bytes(), err)
		}
	}
	b := NewBuffer(3)
	if _, err := io.Copy(b, strings.NewReader("abc")); err != nil || string(b.Bytes()) != "abc" {
		t.Fatalf("bounded write failed: %q %v", b.Bytes(), err)
	}
	if _, err := b.Write([]byte("d")); !errors.Is(err, ErrOutputLimit) {
		t.Fatal("cumulative limit bypassed")
	}
}
