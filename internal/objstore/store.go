package objstore

import (
	"context"
	"io"
)

// Store abstracts blob storage for raw SBOM/SARIF artifacts.
type Store interface {
	Put(ctx context.Context, key string, r io.Reader, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}
