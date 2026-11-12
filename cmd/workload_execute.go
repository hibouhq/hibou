package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/workload"
)

var workloadExecuteCmd = &cobra.Command{
	Use: "workload-execute", Short: "Execute one fixed isolated remediation workload", Hidden: true,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if os.Geteuid() == 0 {
			return errors.New("workload execution requires a non-root identity")
		}
		if err := os.Setenv("TMPDIR", "/work"); err != nil {
			return err
		}
		if err := os.Setenv("HOME", "/work"); err != nil {
			return err
		}
		transport, err := workload.NewWorkerTransport(
			os.Getenv("HIBOU_WORKLOAD_URL"), os.Getenv("HIBOU_WORKLOAD_TOKEN"),
			os.Getenv("HIBOU_WORKLOAD_CA"), os.Getenv("HIBOU_WORKLOAD_POD_UID"),
		)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		data, err := transport.Input(ctx)
		if err != nil {
			return err
		}
		var request remediation.ManagedWorkload
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			return err
		}
		if decoder.Decode(&struct{}{}) != io.EOF || request.Input.BaseSHA != request.Snapshot.SourceSHA ||
			(request.Input.Operation != "generate" && request.Input.Operation != "verify") {
			return errors.New("invalid immutable workload input or operation")
		}
		sourceSHA := request.Input.BaseSHA
		repository, syntheticSHA, cleanup, err := remediation.MaterializeManagedSnapshot(ctx, request.Snapshot, "/work")
		if err != nil {
			return err
		}
		defer cleanup()
		request.Input.BaseSHA = syntheticSHA
		if candidate := request.Input.Candidate; candidate != nil {
			if candidate.Artifact == nil || candidate.Artifact.BaseSHA != sourceSHA {
				return errors.New("verification candidate differs from immutable workload source")
			}
			candidate.Artifact.BaseSHA = syntheticSHA
		}
		match := func(ctx context.Context, purls []string) ([]remediation.AdvisoryMatch, error) {
			body, err := json.Marshal(struct {
				Purls []string `json:"purls"`
			}{Purls: purls})
			if err != nil {
				return nil, err
			}
			response, err := transport.Do(ctx, http.MethodPost, "/match", body)
			if err != nil {
				return nil, err
			}
			var matches []remediation.AdvisoryMatch
			if err := json.Unmarshal(response, &matches); err != nil {
				return nil, err
			}
			return matches, nil
		}
		registry := &http.Client{Transport: &workloadRegistryTransport{worker: transport}, Timeout: 45 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("workload registry redirects are forbidden")
			}}
		result, err := remediation.ExecuteManaged(ctx, request.Input, repository, "/work", match, registry)
		if err != nil {
			return err
		}
		if result.Artifact != nil {
			result.Artifact.BaseSHA = sourceSHA
		}
		output, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return transport.Output(ctx, output)
	},
}

type workloadRegistryTransport struct{ worker *workload.WorkerTransport }

func (t *workloadRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "registry.npmjs.org" || req.URL.User != nil ||
		(req.Method != http.MethodGet && req.Method != http.MethodHead) {
		return nil, errors.New("only approved read-only npm identities may cross the workload broker")
	}
	target := t.worker.ProxyURL() + "/registry" + req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	// #nosec G704 -- fixed authenticated HTTPS attempt origin from WorkerTransport; only the validated npm path/query vary, and RoundTrip independently rejects other destinations.
	clone, err := http.NewRequestWithContext(req.Context(), req.Method, target, nil)
	if err != nil {
		return nil, err
	}
	clone.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	return t.worker.RoundTrip(clone)
}
