package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	UsePathStyle    bool
	UseSSL          bool
}

// S3Store stores blobs in an S3-compatible bucket.
type S3Store struct {
	client *s3.Client
	//nolint:staticcheck // Batch scope explicitly uses the AWS SDK v2 S3 upload manager for streaming unknown-length bodies.
	uploader             *manager.Uploader
	bucket               string
	baseEndpoint         string
	usePathStyle         bool
	useStaticCredentials bool
}

// NewS3Store requires a bucket and region.
// Region stays explicit even for custom endpoints so runtime behavior matches
// AWS SDK expectations instead of silently inventing a value.
func NewS3Store(cfg S3Config) (*S3Store, error) {
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, errors.New("s3 bucket is required")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, errors.New("s3 region is required")
	}

	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}

	accessKeyID := strings.TrimSpace(cfg.AccessKeyID)
	secretAccessKey := strings.TrimSpace(cfg.SecretAccessKey)
	if (accessKeyID == "") != (secretAccessKey == "") {
		return nil, errors.New("both artifact.s3.access_key_id and artifact.s3.secret_access_key must be set together, or neither")
	}

	useStaticCredentials := accessKeyID != "" && secretAccessKey != ""
	if useStaticCredentials {
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				accessKeyID,
				secretAccessKey,
				"",
			),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load s3 config: %w", err)
	}

	baseEndpoint, err := normalizeS3Endpoint(cfg.Endpoint, cfg.UseSSL)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.UsePathStyle
		if baseEndpoint != "" {
			o.BaseEndpoint = aws.String(baseEndpoint)
		}
	})

	return &S3Store{
		client: client,
		//nolint:staticcheck // Batch scope explicitly uses the AWS SDK v2 S3 upload manager for streaming unknown-length bodies.
		uploader:             manager.NewUploader(client),
		bucket:               bucket,
		baseEndpoint:         baseEndpoint,
		usePathStyle:         cfg.UsePathStyle,
		useStaticCredentials: useStaticCredentials,
	}, nil
}

func (s *S3Store) Put(ctx context.Context, key string, r io.Reader, contentType string) error {
	cleaned, err := normalizeObjectKey(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(cleaned),
		Body:   r,
	}
	if trimmed := strings.TrimSpace(contentType); trimmed != "" {
		input.ContentType = aws.String(trimmed)
	}
	//nolint:staticcheck // Batch scope explicitly uses the AWS SDK v2 S3 upload manager for streaming unknown-length bodies.
	if _, err := s.uploader.Upload(ctx, input); err != nil {
		return fmt.Errorf("put object %q: %w", cleaned, err)
	}
	return nil
}

func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	cleaned, err := normalizeObjectKey(key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(cleaned),
	})
	if err != nil {
		if isS3KeyNotFound(err) {
			return nil, fmt.Errorf("object %q: %w", cleaned, fs.ErrNotExist)
		}
		return nil, fmt.Errorf("get object %q: %w", cleaned, err)
	}
	return resp.Body, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	cleaned, err := normalizeObjectKey(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(cleaned),
	})
	if err != nil && !isS3KeyNotFound(err) {
		return fmt.Errorf("delete object %q: %w", cleaned, err)
	}
	return nil
}

func (s *S3Store) Exists(ctx context.Context, key string) (bool, error) {
	cleaned, err := normalizeObjectKey(key)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(cleaned),
	})
	if err == nil {
		return true, nil
	}
	if isS3HeadNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("head object %q: %w", cleaned, err)
}

func normalizeS3Endpoint(endpoint string, useSSL bool) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", nil
	}
	if strings.Contains(trimmed, "://") {
		return trimmed, nil
	}
	scheme := "https://"
	if !useSSL {
		scheme = "http://"
	}
	return scheme + trimmed, nil
}

func isS3KeyNotFound(err error) bool {
	var noSuchKey *types.NoSuchKey
	return errors.As(err, &noSuchKey)
}

func isS3HeadNotFound(err error) bool {
	if isS3KeyNotFound(err) {
		return true
	}
	var notFound *types.NotFound
	return errors.As(err, &notFound)
}
