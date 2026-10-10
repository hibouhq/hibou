package objstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Inventory is what a Store actually holds, as opposed to what the
// snapshot_artifacts ledger says it should hold (ADR-039 §2c).
type Inventory struct {
	Objects   int64
	Bytes     int64
	Truncated bool
	// Volume is set for the filesystem backend only.
	Volume *VolumeStats
}

// VolumeStats is the capacity of the filesystem holding the artifacts.
type VolumeStats struct {
	CapacityBytes int64
	FreeBytes     int64
}

// Inventorier is implemented by stores that can count their own contents.
// It lists and stats only; object bodies are never read.
type Inventorier interface {
	Inventory(ctx context.Context, maxObjects int64) (Inventory, error)
}

var errInventoryLimit = errors.New("inventory object limit reached")

// Inventory pages ListObjectsV2 over the bucket, stopping at maxObjects. Each
// page is one billed LIST request per 1,000 keys.
func (s *S3Store) Inventory(ctx context.Context, maxObjects int64) (Inventory, error) {
	var inv Inventory
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return Inventory{}, fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range page.Contents {
			if inv.Objects >= maxObjects {
				inv.Truncated = true
				return inv, nil
			}
			inv.Objects++
			inv.Bytes += aws.ToInt64(obj.Size)
		}
	}
	return inv, nil
}

// Inventory walks the artifact directory without following symlinks, then
// reports the volume's capacity where the platform supports it.
func (f *FilesystemStore) Inventory(ctx context.Context, maxObjects int64) (Inventory, error) {
	var inv Inventory
	err := filepath.WalkDir(f.baseResolved, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if inv.Objects >= maxObjects {
			inv.Truncated = true
			return errInventoryLimit
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Deleted between the directory read and the stat.
				return nil
			}
			return err
		}
		inv.Objects++
		inv.Bytes += info.Size()
		return nil
	})
	if err != nil && !errors.Is(err, errInventoryLimit) {
		return Inventory{}, fmt.Errorf("walk artifact directory: %w", err)
	}
	if vol, ok := volumeStats(f.baseResolved); ok {
		inv.Volume = &vol
	}
	return inv, nil
}
