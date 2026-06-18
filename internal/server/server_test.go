package server

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/config"
)

func TestRunStalePendingLoopNilWorker(t *testing.T) {
	srv := &Server{}

	srv.runStalePendingLoop(context.Background())
}

func TestNewKeepsRetentionWorkerWhenArtifactStoreInitFails(t *testing.T) {
	artifactRoot := t.TempDir()
	artifactFile, err := os.CreateTemp(artifactRoot, "artifact-store-file")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := artifactFile.Close(); err != nil {
		t.Fatalf("Close artifact file: %v", err)
	}

	srv := New(config.Config{
		ArtifactPath: artifactFile.Name(),
		UploadWindow: 10 * time.Minute,
	}, zerolog.New(io.Discard), nil, nil, nil, nil, os.DirFS(t.TempDir()))

	if srv.retentionWorker == nil {
		t.Fatal("retentionWorker = nil, want non-nil when artifact store init fails")
	}
	if srv.objStore != nil {
		t.Fatal("objStore != nil, want nil when artifact store init fails")
	}
}
