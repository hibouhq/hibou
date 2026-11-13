package workload

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(".", ".workload-test-"+randomID())
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}
func certPEM(s *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

type fakeAPI struct {
	mu                sync.Mutex
	job               Job
	pod               Pod
	created           chan Job
	deleted           chan string
	succeeded, failed bool
	podUID, ownerUID  string
	version           string
	listed            []Job
	deny              int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if f.deny != 0 {
		w.WriteHeader(f.deny)
		_, _ = io.WriteString(w, `{"message":"sensitive secret NEVER expose"}`)
		return
	}
	switch {
	case r.URL.Path == "/version":
		_ = json.NewEncoder(w).Encode(map[string]string{"major": "1", "minor": f.version})
	case r.Method == http.MethodPost:
		var j Job
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		j.Metadata.UID = "job-uid"
		if r.URL.Query().Get("dryRun") != "All" {
			f.job = j
			f.pod = Pod{Metadata: Metadata{Name: "pod-one", UID: "pod-uid", OwnerReferences: []OwnerReference{{"batch/v1", "Job", j.Metadata.Name, "job-uid", true}}}, Spec: j.Spec.Template.Spec}
			f.pod.Status.Phase = "Running"
			f.created <- j
		}
		_ = json.NewEncoder(w).Encode(j)
	case r.Method == http.MethodDelete:
		var options struct {
			PropagationPolicy string
			Preconditions     struct{ UID string }
		}
		if err := json.NewDecoder(r.Body).Decode(&options); err != nil || options.PropagationPolicy != "Foreground" || options.Preconditions.UID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.deleted <- options.Preconditions.UID
		_, _ = io.WriteString(w, `{}`)
	case strings.Contains(r.URL.Path, "/pods/"):
		p := f.pod
		if f.podUID != "" {
			p.Metadata.UID = f.podUID
		}
		if f.ownerUID != "" {
			p.Metadata.OwnerReferences = append([]OwnerReference(nil), p.Metadata.OwnerReferences...)
			p.Metadata.OwnerReferences[0].UID = f.ownerUID
		}
		_ = json.NewEncoder(w).Encode(p)
	case strings.HasSuffix(r.URL.Path, "/pods"):
		p := f.pod
		if f.podUID != "" {
			p.Metadata.UID = f.podUID
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []Pod{p}})
	case strings.HasSuffix(r.URL.Path, "/jobs"):
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.listed})
	default:
		j := f.job
		if j.Metadata.UID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.succeeded {
			j.Status.Succeeded = 1
		}
		if f.failed {
			j.Status.Failed = 1
		}
		_ = json.NewEncoder(w).Encode(j)
	}
}

type fixture struct {
	runner *Runner
	broker *Broker
	server *httptest.Server
	api    *fakeAPI
	client *Client
	cfg    Config
}

func setup(t *testing.T) fixture {
	t.Helper()
	api := &fakeAPI{created: make(chan Job, 10), deleted: make(chan string, 10), version: "36"}
	s := httptest.NewTLSServer(api)
	t.Cleanup(s.Close)
	dir := testDir(t)
	token := filepath.Join(dir, "token")
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(token, []byte("token-one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte(certPEM(s)), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(APIConfig{s.URL, token, ca})
	if err != nil {
		t.Fatal(err)
	}
	b := NewBroker()
	bs := httptest.NewTLSServer(b)
	t.Cleanup(bs.Close)
	cfg := Config{Namespace: "execution", ControllerNamespace: "app", Image: "mirror.internal/workload@sha256:" + strings.Repeat("a", 64), RuntimeClass: "sandbox", RuntimeValidated: true, ServiceAccount: "remediation", BrokerURL: bs.URL, CABundle: certPEM(bs), PollInterval: 100 * time.Millisecond, Deadline: 3 * time.Second, MaxInputBytes: 1024, MaxOutputBytes: 1024}
	r, err := NewRunner(cfg, c, b)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{r, b, bs, api, c, cfg}
}
func workerFor(t *testing.T, f fixture, j Job) *WorkerTransport {
	t.Helper()
	env := j.Spec.Template.Spec.Containers[0].Env
	w, err := NewWorkerTransport(env[0].Value, env[1].Value, env[2].Value, "pod-uid")
	if err != nil {
		t.Fatal(err)
	}
	return w
}
func waitInput(t *testing.T, w *WorkerTransport) []byte {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		b, err := w.Input(context.Background())
		if err == nil {
			return b
		}
		select {
		case <-deadline.C:
			t.Fatalf("broker did not accept identity: %v", err)
		case <-tick.C:
		}
	}
}
func request() Request {
	return Request{ID: "intent", Fence: "fence", Class: ClassRemediation, Input: []byte("source"), OnIdentity: func(context.Context, Identity) error { return nil }}
}

func TestRunnerSpecBrokerAndLifecycle(t *testing.T) {
	f := setup(t)
	if err := f.runner.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	req := request()
	var identities atomic.Int32
	req.OnIdentity = func(_ context.Context, i Identity) error {
		if i.JobUID != "job-uid" {
			t.Error("wrong persisted Job UID")
		}
		identities.Add(1)
		return nil
	}
	req.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/match" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Hibou-Pod-UID") != "" {
			t.Error("delegated handler scope/credential leak")
		}
		_, _ = io.WriteString(w, "matched")
	})
	type outcome struct {
		r Result
		e error
	}
	done := make(chan outcome, 1)
	go func() { r, e := f.runner.Run(context.Background(), req); done <- outcome{r, e} }()
	j := <-f.api.created
	p := j.Spec.Template.Spec
	c := p.Containers[0]
	if p.ActiveDeadlineSeconds != j.Spec.ActiveDeadlineSeconds || p.ActiveDeadlineSeconds < 1 {
		t.Fatal("Pod must retain its own immutable deadline even if Job is orphan-deleted")
	}
	if p.HostUsers || p.AutomountServiceAccountToken || p.HostNetwork || p.HostPID || p.HostIPC || p.RuntimeClassName != "sandbox" || p.ServiceAccountName != "remediation" || !p.SecurityContext.RunAsNonRoot || p.SecurityContext.RunAsUser != UID || p.SecurityContext.RunAsGroup != UID || p.SecurityContext.SeccompProfile.Type != "RuntimeDefault" {
		t.Fatal("unsafe Pod baseline")
	}
	if strings.Join(c.Command, " ") != "/usr/local/bin/hibou workload-execute" || len(c.Env) != 4 || c.SecurityContext.AllowPrivilegeEscalation || !c.SecurityContext.ReadOnlyRootFilesystem || strings.Join(c.SecurityContext.Capabilities.Drop, ",") != "ALL" || len(p.Volumes) != 1 || p.Volumes[0].Name != "scratch" || len(c.VolumeMounts) != 1 || c.ImagePullPolicy != "IfNotPresent" {
		t.Fatal("unsafe launcher")
	}
	raw, _ := json.Marshal(j)
	for _, bad := range []string{"hostPath", "persistentVolumeClaim", "secretKeyRef", "envFrom", "/var/run", "/bin/sh", `"Succeeded"`, `"Requests"`, `"creationTimestamp"`} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("unexpected %s", bad)
		}
	}
	for _, key := range []string{"cpu", "memory", "ephemeral-storage"} {
		if c.Resources.Limits[key] == "" || c.Resources.Requests[key] == "" {
			t.Fatal("missing resource bound")
		}
	}
	w := workerFor(t, f, j)
	if string(waitInput(t, w)) != "source" {
		t.Fatal("input mismatch")
	}
	data, err := w.Do(context.Background(), "POST", "/match", []byte("{}"))
	if err != nil || string(data) != "matched" {
		t.Fatalf("proxy: %s %v", data, err)
	}
	if err := w.Output(context.Background(), []byte("candidate")); err != nil {
		t.Fatal(err)
	}
	if err := w.Output(context.Background(), []byte("duplicate")); err == nil {
		t.Fatal("duplicate result accepted")
	}
	f.api.mu.Lock()
	f.api.succeeded = true
	f.api.pod.Status.Phase = "Succeeded"
	f.api.mu.Unlock()
	out := <-done
	if out.e != nil || string(out.r.Output) != "candidate" || out.r.JobUID != "job-uid" || out.r.PodUID != "pod-uid" || identities.Load() < 4 {
		t.Fatalf("result: %#v %v identities=%d", out.r, out.e, identities.Load())
	}
	if uid := <-f.api.deleted; uid != "job-uid" {
		t.Fatalf("delete UID %q", uid)
	}
	if _, err := w.Input(context.Background()); err == nil {
		t.Fatal("late capability accepted")
	}
}
func TestBrokerRejectsIdentityAndAuthentication(t *testing.T) {
	for _, mode := range []string{"token", "pod-uid", "owner-uid", "job-uid", "fence"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, e := f.runner.Run(ctx, request()); done <- e }()
			j := <-f.api.created
			w := workerFor(t, f, j)
			waitInput(t, w)
			switch mode {
			case "token":
				w.token = strings.Repeat("b", 64)
			case "pod-uid":
				w.podUID = "copied-labels"
			case "owner-uid":
				f.api.mu.Lock()
				f.api.ownerUID = "another-job"
				f.api.mu.Unlock()
			case "job-uid":
				f.api.mu.Lock()
				f.api.job.Metadata.UID = "replacement"
				f.api.mu.Unlock()
			case "fence":
				f.api.mu.Lock()
				labels := map[string]string{}
				for k, v := range f.api.job.Metadata.Labels {
					labels[k] = v
				}
				labels[fenceLabel] = "different"
				f.api.job.Metadata.Labels = labels
				f.api.mu.Unlock()
			}
			if err := w.Output(context.Background(), []byte("untrusted")); err == nil {
				t.Fatal("invalid identity accepted")
			}
			cancel()
			if err := <-done; err == nil {
				t.Fatal("cancelled attempt succeeded")
			}
			<-f.api.deleted
		})
	}
}
func TestCancellationRevocationAndFenceLoss(t *testing.T) {
	for _, mode := range []string{"cancel", "claim-lost", "deadline", "job-failed", "missing-output"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			if mode == "deadline" {
				f.runner.config.Deadline = time.Second
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var lost atomic.Bool
			req := request()
			req.OnIdentity = func(context.Context, Identity) error {
				if lost.Load() {
					return errors.New("lost fence")
				}
				return nil
			}
			done := make(chan error, 1)
			go func() { _, e := f.runner.Run(ctx, req); done <- e }()
			j := <-f.api.created
			w := workerFor(t, f, j)
			waitInput(t, w)
			switch mode {
			case "cancel":
				cancel()
			case "claim-lost":
				lost.Store(true)
				if err := w.Output(ctx, []byte("stale")); err == nil {
					t.Fatal("lost fence accepted")
				}
			case "job-failed":
				f.api.mu.Lock()
				f.api.failed = true
				f.api.mu.Unlock()
			case "missing-output":
				f.api.mu.Lock()
				f.api.succeeded = true
				f.api.mu.Unlock()
			}
			if err := <-done; err == nil {
				t.Fatal("failure succeeded")
			}
			<-f.api.deleted
			if err := w.Output(context.Background(), []byte("late")); err == nil {
				t.Fatal("late result accepted")
			}
		})
	}
}
func TestBoundedBrokerAndScopedStreaming(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := request()
	req.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 1025)) })
	done := make(chan error, 1)
	go func() { _, e := f.runner.Run(ctx, req); done <- e }()
	j := <-f.api.created
	w := workerFor(t, f, j)
	waitInput(t, w)
	if err := w.Output(ctx, []byte(strings.Repeat("x", 1025))); err == nil {
		t.Fatal("oversize output accepted")
	}
	res, err := w.HTTPClient().Get(w.ProxyURL() + "/registry/archive")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatal("oversize delegated response accepted")
	}
	for _, target := range []string{f.server.URL + "/other", "https://example.invalid/", w.base + "/input"} {
		if res, err := w.HTTPClient().Get(target); err == nil {
			res.Body.Close()
			t.Fatal("out-of-scope request accepted")
		}
	}
	b := &boundedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("12345")), remaining: 4}
	if _, err := io.ReadAll(b); err == nil {
		t.Fatal("stream truncation accepted")
	}
	cancel()
	<-done
	<-f.api.deleted
}
func TestClientRotationStrictResponsesAndPreflight(t *testing.T) {
	f := setup(t)
	var auth []string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"major":"1","minor":"36"}`)
	}))
	defer s.Close()
	f.client.base = s.URL
	f.client.http = s.Client()
	if err := f.client.version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.client.tokenFile, []byte("rotated-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.client.version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(auth) != 2 || auth[0] != "Bearer token-one" || auth[1] != "Bearer rotated-token" {
		t.Fatal("token rotation not honored")
	}
	for _, tc := range []struct {
		body, content string
		code          int
	}{{`{} {}`, "application/json", 200}, {`{`, "application/json", 200}, {"[]", "text/html", 200}, {strings.Repeat("x", (2<<20)+1), "application/json", 200}, {`{"message":"secret"}`, "application/json", 403}} {
		s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.content)
			w.WriteHeader(tc.code)
			_, _ = io.WriteString(w, tc.body)
		})
		if err := f.client.version(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("response must fail closed without body leak: %v", err)
		}
	}
}
func TestVersionMatrixConfigAndOrphanOwnership(t *testing.T) {
	f := setup(t)
	for _, version := range []string{"32", "37", "garbage"} {
		f.api.mu.Lock()
		f.api.version = version
		f.api.mu.Unlock()
		if err := f.runner.Ready(context.Background()); err == nil {
			t.Fatalf("unsupported version %s", version)
		}
	}
	for _, version := range []string{"33", "34+", "35", "36"} {
		f.api.mu.Lock()
		f.api.version = version
		f.api.mu.Unlock()
		if err := f.runner.Ready(context.Background()); err != nil {
			t.Fatalf("supported version %s: %v", version, err)
		}
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Namespace = c.ControllerNamespace }, func(c *Config) { c.Image = "image:latest" },
		func(c *Config) { c.RuntimeValidated = false }, func(c *Config) { c.BrokerURL = "http://broker" },
		func(c *Config) { c.CABundle = "" }, func(c *Config) { c.MaxOutputBytes = MaxBodyBytes + 1 },
		func(c *Config) { c.PollInterval = time.Millisecond },
	} {
		c := f.cfg
		mutate(&c)
		if _, err := NewRunner(c, f.client, f.broker); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	j := f.runner.config.job(randomID(), randomToken(), "orphan")
	j.Metadata.UID = "orphan-uid"
	old := time.Now().Add(-time.Hour)
	j.Metadata.CreationTimestamp = &old
	f.api.mu.Lock()
	f.api.listed = []Job{j}
	f.api.mu.Unlock()
	if err := f.runner.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if uid := <-f.api.deleted; uid != "orphan-uid" {
		t.Fatal("orphan UID lost")
	}
	fresh := time.Now()
	j.Metadata.CreationTimestamp = &fresh
	f.api.mu.Lock()
	f.api.listed = []Job{j}
	f.api.mu.Unlock()
	if err := f.runner.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.api.deleted:
		t.Fatal("fresh replica Job deleted")
	default:
	}
	j.Metadata.Labels[ownerLabel] = "other-controller"
	f.api.mu.Lock()
	f.api.listed = []Job{j}
	f.api.mu.Unlock()
	if err := f.runner.Cleanup(context.Background()); err == nil {
		t.Fatal("foreign orphan deleted")
	}
	select {
	case <-f.api.deleted:
		t.Fatal("foreign deletion")
	default:
	}
	if _, err := f.runner.Run(context.Background(), Request{Class: "scanner"}); err == nil {
		t.Fatal("future class inherited remediation permission")
	}
}

func TestBrokerRequiresTLSAndRejectsQueries(t *testing.T) {
	b := NewBroker()
	for _, target := range []string{"/v1/workloads/attempt/input", "/v1/workloads/attempt/input?escape=1"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("plaintext accepted: %d", w.Code)
		}

		req.TLS = &tls.ConnectionState{}
		w = httptest.NewRecorder()
		b.ServeHTTP(w, req)
		if target[len(target)-1] == '1' && w.Code != 400 {
			t.Fatal("query accepted")
		}
	}
}

func TestReadyRejectsDroppedUserNamespaces(t *testing.T) {
	f := setup(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/version" {
			_, _ = io.WriteString(w, `{"major":"1","minor":"33"}`)
			return
		}
		var j map[string]any
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			t.Error(err)
			return
		}
		p := j["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		delete(p, "hostUsers")
		_ = json.NewEncoder(w).Encode(j)
	}))
	defer server.Close()
	f.client.base = server.URL
	f.client.http = server.Client()
	if err := f.runner.Ready(context.Background()); err == nil {
		t.Fatal("server silently dropped required user namespace field")
	}
}

func ExampleWorkerTransport_ProxyURL() {
	w := &WorkerTransport{base: "https://broker.app.svc:8443/v1/workloads/attempt"}
	fmt.Println(w.ProxyURL())
	// Output: https://broker.app.svc:8443/v1/workloads/attempt/proxy
}
