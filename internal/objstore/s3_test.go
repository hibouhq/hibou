package objstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Unit tests stay local to constructor and key validation logic.
// Live S3 integration is intentionally out of scope here.
func TestNewS3StoreRequiresBucket(t *testing.T) {
	_, err := NewS3Store(S3Config{Region: "us-east-1"})
	if err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("NewS3Store() error = %v, want missing bucket", err)
	}
}

func TestNewS3StoreRequiresRegion(t *testing.T) {
	_, err := NewS3Store(S3Config{Bucket: "hibou-artifacts"})
	if err == nil || !strings.Contains(err.Error(), "region") {
		t.Fatalf("NewS3Store() error = %v, want missing region", err)
	}
}

func TestNewS3StoreNormalizesEndpointAndUsesStaticCredentials(t *testing.T) {
	store, err := NewS3Store(S3Config{
		Endpoint:        "s3.internal:9000",
		Region:          "us-east-1",
		Bucket:          "hibou-artifacts",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		UsePathStyle:    true,
		UseSSL:          false,
	})
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}
	if store.baseEndpoint != "http://s3.internal:9000" {
		t.Fatalf("baseEndpoint = %q, want http://s3.internal:9000", store.baseEndpoint)
	}
	if !store.usePathStyle {
		t.Fatal("usePathStyle = false, want true")
	}
	if !store.useStaticCredentials {
		t.Fatal("useStaticCredentials = false, want true")
	}
	if store.bucket != "hibou-artifacts" {
		t.Fatalf("bucket = %q, want hibou-artifacts", store.bucket)
	}
}

func TestNewS3StoreUsesDefaultCredentialChainWhenKeysMissing(t *testing.T) {
	store, err := NewS3Store(S3Config{
		Endpoint:     "https://s3.internal",
		Region:       "us-east-1",
		Bucket:       "hibou-artifacts",
		UsePathStyle: true,
		UseSSL:       true,
	})
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}
	if store.useStaticCredentials {
		t.Fatal("useStaticCredentials = true, want false")
	}
	if store.baseEndpoint != "https://s3.internal" {
		t.Fatalf("baseEndpoint = %q, want https://s3.internal", store.baseEndpoint)
	}
	if !store.usePathStyle {
		t.Fatal("usePathStyle = false, want true")
	}
}

func TestNewS3StoreRejectsPartialStaticCredentials(t *testing.T) {
	_, err := NewS3Store(S3Config{
		Endpoint:     "https://s3.internal",
		Region:       "us-east-1",
		Bucket:       "hibou-artifacts",
		AccessKeyID:  "access",
		UsePathStyle: true,
		UseSSL:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "both artifact.s3.access_key_id and artifact.s3.secret_access_key must be set together, or neither") {
		t.Fatalf("NewS3Store() error = %v, want partial credentials failure", err)
	}
}

func TestS3NotFoundHelpersOnlyMatchObjectErrors(t *testing.T) {
	t.Run("key not found", func(t *testing.T) {
		if !isS3KeyNotFound(&types.NoSuchKey{}) {
			t.Fatal("isS3KeyNotFound(NoSuchKey) = false, want true")
		}
		if !isS3HeadNotFound(&types.NoSuchKey{}) {
			t.Fatal("isS3HeadNotFound(NoSuchKey) = false, want true")
		}
	})

	t.Run("head not found", func(t *testing.T) {
		if !isS3HeadNotFound(&types.NotFound{}) {
			t.Fatal("isS3HeadNotFound(NotFound) = false, want true")
		}
		if isS3KeyNotFound(&types.NotFound{}) {
			t.Fatal("isS3KeyNotFound(NotFound) = true, want false")
		}
	})

	t.Run("bucket missing is not object missing", func(t *testing.T) {
		if isS3KeyNotFound(&types.NoSuchBucket{}) {
			t.Fatal("isS3KeyNotFound(NoSuchBucket) = true, want false")
		}
		if isS3HeadNotFound(&types.NoSuchBucket{}) {
			t.Fatal("isS3HeadNotFound(NoSuchBucket) = true, want false")
		}
	})
}

func TestS3StoreRejectsInvalidKeysBeforeClientCall(t *testing.T) {
	store, err := NewS3Store(S3Config{
		Endpoint:     "127.0.0.1:9000",
		Region:       "us-east-1",
		Bucket:       "hibou-artifacts",
		UsePathStyle: true,
		UseSSL:       false,
	})
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}

	ctx := context.Background()
	for _, key := range []string{"", "../escape.json", "acme/../../escape.json", "/tmp/escape.json"} {
		if err := store.Put(ctx, key, strings.NewReader("{}"), "application/json"); !errors.Is(err, errInvalidKey) {
			t.Fatalf("Put(%q) error = %v, want errInvalidKey", key, err)
		}
		if _, err := store.Get(ctx, key); !errors.Is(err, errInvalidKey) {
			t.Fatalf("Get(%q) error = %v, want errInvalidKey", key, err)
		}
		if err := store.Delete(ctx, key); !errors.Is(err, errInvalidKey) {
			t.Fatalf("Delete(%q) error = %v, want errInvalidKey", key, err)
		}
		if _, err := store.Exists(ctx, key); !errors.Is(err, errInvalidKey) {
			t.Fatalf("Exists(%q) error = %v, want errInvalidKey", key, err)
		}
	}
}
