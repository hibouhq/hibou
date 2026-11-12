// Package workload provides the ADR-056 remediation-only Kubernetes execution
// boundary. It intentionally uses the standard library instead of importing the
// client-go dependency graph for a small, fixed, versioned REST surface.
package workload

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ClassRemediation = "remediation"
	UID              = 65532
	MaxBodyBytes     = 192 << 20
)

var (
	dnsName     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	digestImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
)

type Resources struct {
	CPURequest, CPULimit, MemoryRequest, MemoryLimit, StorageRequest, StorageLimit string
}

func DefaultResources() Resources {
	return Resources{"250m", "2", "256Mi", "2Gi", "1Gi", "2Gi"}
}

type Config struct {
	Namespace, ControllerNamespace, Image, RuntimeClass, ServiceAccount string
	BrokerURL, CABundle                                                 string
	ImagePullSecrets                                                    []string
	// RuntimeValidated attests operator qualification of user namespaces and the
	// chosen sandbox runtime on every eligible node; API version alone cannot.
	RuntimeValidated              bool
	Deadline, PollInterval        time.Duration
	MaxInputBytes, MaxOutputBytes int64
	Resources                     Resources
}

func (c Config) normalized() (Config, error) {
	for _, s := range []string{c.Namespace, c.ControllerNamespace, c.RuntimeClass, c.ServiceAccount} {
		if len(s) > 63 || !dnsName.MatchString(s) {
			return c, errors.New("workload requires valid namespace, runtime class and service account names")
		}
	}
	if c.Namespace == c.ControllerNamespace {
		return c, errors.New("execution namespace must differ from controller/API namespace")
	}
	seen := map[string]bool{}
	secretName := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	if len(c.ImagePullSecrets) > 8 {
		return c, errors.New("at most eight approved image pull secrets are supported")
	}
	for _, name := range c.ImagePullSecrets {
		if len(name) > 253 || !secretName.MatchString(name) || seen[name] {
			return c, errors.New("invalid or duplicate execution-namespace image pull secret name")
		}
		seen[name] = true
	}
	c.ImagePullSecrets = append([]string(nil), c.ImagePullSecrets...)
	if !digestImage.MatchString(c.Image) {
		return c, errors.New("workload image must be pinned by sha256 digest")
	}
	if !c.RuntimeValidated {
		return c, errors.New("operator must validate sandbox runtime and user namespace support")
	}
	u, err := secureURL(c.BrokerURL)
	if err != nil || u.Path != "" {
		return c, errors.New("broker URL must be an HTTPS origin without path")
	}
	if _, err := tlsClient(c.CABundle); err != nil {
		return c, err
	}
	if c.Deadline == 0 {
		c.Deadline = 10 * time.Minute
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.MaxInputBytes == 0 {
		c.MaxInputBytes = MaxBodyBytes
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = MaxBodyBytes
	}
	if c.Deadline < time.Second || c.Deadline > 30*time.Minute || c.PollInterval < 100*time.Millisecond || c.PollInterval > 30*time.Second {
		return c, errors.New("invalid workload deadline or polling interval")
	}
	if c.MaxInputBytes < 1 || c.MaxInputBytes > MaxBodyBytes || c.MaxOutputBytes < 1 || c.MaxOutputBytes > MaxBodyBytes {
		return c, errors.New("invalid workload transport bounds")
	}
	if c.Resources == (Resources{}) {
		c.Resources = DefaultResources()
	}
	quantity := regexp.MustCompile(`^[1-9][0-9]*(m|Ki|Mi|Gi)?$`)
	for _, v := range []string{c.Resources.CPURequest, c.Resources.CPULimit, c.Resources.MemoryRequest, c.Resources.MemoryLimit, c.Resources.StorageRequest, c.Resources.StorageLimit} {
		if !quantity.MatchString(v) {
			return c, errors.New("invalid workload resource quantity")
		}
	}
	return c, nil
}

// ConfigFromEnv is shared by the dedicated controller, not the API process.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Namespace: os.Getenv("HIBOU_WORKLOAD_NAMESPACE"), ControllerNamespace: os.Getenv("HIBOU_WORKLOAD_CONTROLLER_NAMESPACE"),
		Image: os.Getenv("HIBOU_WORKLOAD_IMAGE"), RuntimeClass: os.Getenv("HIBOU_WORKLOAD_RUNTIME_CLASS"),
		ServiceAccount: os.Getenv("HIBOU_WORKLOAD_SERVICE_ACCOUNT"), BrokerURL: os.Getenv("HIBOU_WORKLOAD_BROKER_URL"),
		CABundle: os.Getenv("HIBOU_WORKLOAD_CA"), RuntimeValidated: os.Getenv("HIBOU_WORKLOAD_RUNTIME_VALIDATED") == "true",
		Resources: DefaultResources(),
	}
	if names := os.Getenv("HIBOU_WORKLOAD_IMAGE_PULL_SECRETS"); names != "" {
		c.ImagePullSecrets = strings.Split(names, ",")
		for i := range c.ImagePullSecrets {
			c.ImagePullSecrets[i] = strings.TrimSpace(c.ImagePullSecrets[i])
		}
	}
	for _, p := range []struct {
		key string
		dst *string
	}{
		{"CPU_REQUEST", &c.Resources.CPURequest}, {"CPU_LIMIT", &c.Resources.CPULimit},
		{"MEMORY_REQUEST", &c.Resources.MemoryRequest}, {"MEMORY_LIMIT", &c.Resources.MemoryLimit},
		{"STORAGE_REQUEST", &c.Resources.StorageRequest}, {"STORAGE_LIMIT", &c.Resources.StorageLimit},
	} {
		if v := os.Getenv("HIBOU_WORKLOAD_" + p.key); v != "" {
			*p.dst = v
		}
	}
	if v := os.Getenv("HIBOU_WORKLOAD_DEADLINE_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1800 {
			return c, errors.New("invalid workload deadline")
		}
		c.Deadline = time.Duration(n) * time.Second
	}
	return c.normalized()
}

func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return nil, errors.New("HTTPS URL without credentials, query or fragment required")
	}
	return u, nil
}

func tlsClient(ca string) (*http.Client, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca)) {
		return nil, errors.New("valid public CA PEM required")
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 8, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects forbidden") },
	}, nil
}

func invalidStatus(code int) error { return fmt.Errorf("workload endpoint returned HTTP %d", code) }
func boundedString(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsAny(s, "\x00\r\n")
}
