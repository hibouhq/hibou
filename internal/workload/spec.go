package workload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Metadata struct {
	Name              string            `json:"name,omitempty"`
	UID               string            `json:"uid,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
	DeletionTimestamp *string           `json:"deletionTimestamp,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
}
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}
type Job struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       JobSpec  `json:"spec"`
	Status     struct {
		Succeeded  int `json:"succeeded,omitempty"`
		Failed     int `json:"failed,omitempty"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions,omitempty"`
	} `json:"status,omitempty"`
}
type JobSpec struct {
	BackoffLimit            int   `json:"backoffLimit"`
	ActiveDeadlineSeconds   int64 `json:"activeDeadlineSeconds"`
	TTLSecondsAfterFinished int   `json:"ttlSecondsAfterFinished"`
	Completions             int   `json:"completions"`
	Parallelism             int   `json:"parallelism"`
	Template                struct {
		Metadata Metadata `json:"metadata"`
		Spec     PodSpec  `json:"spec"`
	} `json:"template"`
}
type Pod struct {
	Metadata Metadata `json:"metadata"`
	Spec     PodSpec  `json:"spec"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}
type PodSpec struct {
	hostUsersPresent              bool
	HostUsers                     bool                   `json:"hostUsers"`
	HostNetwork                   bool                   `json:"hostNetwork"`
	HostPID                       bool                   `json:"hostPID"`
	HostIPC                       bool                   `json:"hostIPC"`
	AutomountServiceAccountToken  bool                   `json:"automountServiceAccountToken"`
	ServiceAccountName            string                 `json:"serviceAccountName"`
	ImagePullSecrets              []LocalObjectReference `json:"imagePullSecrets,omitempty"`
	RuntimeClassName              string                 `json:"runtimeClassName"`
	RestartPolicy                 string                 `json:"restartPolicy"`
	ActiveDeadlineSeconds         int64                  `json:"activeDeadlineSeconds"`
	TerminationGracePeriodSeconds int                    `json:"terminationGracePeriodSeconds"`
	EnableServiceLinks            bool                   `json:"enableServiceLinks"`
	SecurityContext               PodSecurity            `json:"securityContext"`
	Containers                    []Container            `json:"containers"`
	Volumes                       []Volume               `json:"volumes"`
}
type LocalObjectReference struct {
	Name string `json:"name"`
}

func (c Config) approvedPullSecrets(p PodSpec) bool {
	if len(p.ImagePullSecrets) != len(c.ImagePullSecrets) {
		return false
	}
	for i, secret := range p.ImagePullSecrets {
		if secret.Name != c.ImagePullSecrets[i] {
			return false
		}
	}
	return true
}

func (p *PodSpec) UnmarshalJSON(data []byte) error {
	type plain PodSpec
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*p = PodSpec(decoded)
	v, ok := fields["hostUsers"]
	p.hostUsersPresent = ok && string(v) != "null"
	return nil
}

type PodSecurity struct {
	RunAsNonRoot   bool `json:"runAsNonRoot"`
	RunAsUser      int  `json:"runAsUser"`
	RunAsGroup     int  `json:"runAsGroup"`
	FSGroup        int  `json:"fsGroup"`
	SeccompProfile struct {
		Type string `json:"type"`
	} `json:"seccompProfile"`
}
type Container struct {
	Name            string   `json:"name"`
	Image           string   `json:"image"`
	ImagePullPolicy string   `json:"imagePullPolicy"`
	Command         []string `json:"command"`
	Env             []Env    `json:"env"`
	Resources       struct {
		Requests map[string]string `json:"requests"`
		Limits   map[string]string `json:"limits"`
	} `json:"resources"`
	SecurityContext struct {
		AllowPrivilegeEscalation bool `json:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   bool `json:"readOnlyRootFilesystem"`
		Privileged               bool `json:"privileged"`
		Capabilities             struct {
			Drop []string `json:"drop"`
		} `json:"capabilities"`
	} `json:"securityContext"`
	VolumeMounts []VolumeMount `json:"volumeMounts"`
	WorkingDir   string        `json:"workingDir"`
}
type Env struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	ValueFrom *struct {
		FieldRef struct {
			FieldPath string `json:"fieldPath"`
		} `json:"fieldRef"`
	} `json:"valueFrom,omitempty"`
}
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}
type Volume struct {
	Name     string `json:"name"`
	EmptyDir struct {
		SizeLimit string `json:"sizeLimit"`
	} `json:"emptyDir"`
}

const ownerLabel = "workload.hibou.dev/controller"
const attemptLabel = "workload.hibou.dev/attempt"
const fenceLabel = "workload.hibou.dev/fence"
const classLabel = "workload.hibou.dev/class"

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:])[:40] }
func (c Config) owner() string {
	return hash(c.ControllerNamespace + "/" + c.Namespace + "/" + c.ServiceAccount)
}
func (c Config) job(attempt, token, fence string) Job {
	labels := map[string]string{ownerLabel: c.owner(), attemptLabel: attempt, fenceLabel: hash(fence), classLabel: ClassRemediation}
	j := Job{APIVersion: "batch/v1", Kind: "Job", Metadata: Metadata{Name: "hibou-" + attempt, Labels: labels}}
	j.Spec.BackoffLimit = 0
	j.Spec.Completions = 1
	j.Spec.Parallelism = 1
	j.Spec.ActiveDeadlineSeconds = int64(c.Deadline.Seconds())
	j.Spec.TTLSecondsAfterFinished = 300
	j.Spec.Template.Metadata = Metadata{Labels: labels}
	p := PodSpec{HostUsers: false, ServiceAccountName: c.ServiceAccount, RuntimeClassName: c.RuntimeClass, RestartPolicy: "Never", ActiveDeadlineSeconds: int64(c.Deadline.Seconds()), TerminationGracePeriodSeconds: 10}
	for _, name := range c.ImagePullSecrets {
		p.ImagePullSecrets = append(p.ImagePullSecrets, LocalObjectReference{Name: name})
	}
	p.SecurityContext = PodSecurity{RunAsNonRoot: true, RunAsUser: UID, RunAsGroup: UID, FSGroup: UID}
	p.SecurityContext.SeccompProfile.Type = "RuntimeDefault"
	w := Container{Name: "workload", Image: c.Image, ImagePullPolicy: "IfNotPresent", Command: []string{"/usr/local/bin/hibou", "workload-execute"}, WorkingDir: "/scratch"}
	w.SecurityContext.ReadOnlyRootFilesystem = true
	w.SecurityContext.Capabilities.Drop = []string{"ALL"}
	w.Resources.Requests = map[string]string{"cpu": c.Resources.CPURequest, "memory": c.Resources.MemoryRequest, "ephemeral-storage": c.Resources.StorageRequest}
	w.Resources.Limits = map[string]string{"cpu": c.Resources.CPULimit, "memory": c.Resources.MemoryLimit, "ephemeral-storage": c.Resources.StorageLimit}
	w.Env = []Env{{Name: "HIBOU_WORKLOAD_URL", Value: c.BrokerURL + "/v1/workloads/" + attempt}, {Name: "HIBOU_WORKLOAD_TOKEN", Value: token}, {Name: "HIBOU_WORKLOAD_CA", Value: c.CABundle}, {Name: "HIBOU_WORKLOAD_POD_UID"}}
	_ = json.Unmarshal([]byte(`{"fieldRef":{"fieldPath":"metadata.uid"}}`), &w.Env[3].ValueFrom)
	w.VolumeMounts = []VolumeMount{{"scratch", "/scratch"}}
	p.Containers = []Container{w}
	p.Volumes = []Volume{{Name: "scratch"}}
	p.Volumes[0].EmptyDir.SizeLimit = c.Resources.StorageRequest
	j.Spec.Template.Spec = p
	return j
}
