{{- define "hibou.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hibou.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "hibou.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hibou.labels" -}}
app.kubernetes.io/name: {{ include "hibou.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{- define "hibou.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hibou.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "hibou.sessionSecretName" -}}
{{- if .Values.hibou.sessionSecretExistingSecret -}}
{{- .Values.hibou.sessionSecretExistingSecret -}}
{{- else -}}
{{- printf "%s-session" (include "hibou.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "hibou.postgresqlServiceName" -}}
{{- printf "%s-postgresql" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.postgresqlSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else if .Values.cnpg.cluster.enabled -}}
{{- printf "%s-pg-app" (include "hibou.fullname" .) -}}
{{- else -}}
{{- printf "%s-postgresql" (include "hibou.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "hibou.postgresqlSecretKey" -}}
{{- if .Values.cnpg.cluster.enabled -}}
uri
{{- else -}}
url
{{- end -}}
{{- end -}}

{{- define "hibou.trivyServiceName" -}}
{{- printf "%s-trivy" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.seaweedfsServiceName" -}}
{{- printf "%s-seaweedfs" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.seaweedfsSecretName" -}}
{{- if .Values.seaweedfs.accessKeyExistingSecret -}}
{{- .Values.seaweedfs.accessKeyExistingSecret -}}
{{- else -}}
{{- printf "%s-seaweedfs" (include "hibou.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "hibou.artifactBackend" -}}
{{- if .Values.artifact.backend -}}
{{- .Values.artifact.backend -}}
{{- else if .Values.seaweedfs.enabled -}}
s3
{{- else -}}
filesystem
{{- end -}}
{{- end -}}

{{- define "hibou.artifactFilesystemPath" -}}
{{- default "/data/artifacts" .Values.artifact.path -}}
{{- end -}}

{{- define "hibou.artifactFilesystemPVCName" -}}
{{- printf "%s-artifact-filesystem" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.artifactFilesystemPersistenceEnabled" -}}
{{- if and (eq (include "hibou.artifactBackend" .) "filesystem") .Values.artifact.filesystem.persistence.enabled -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{- define "hibou.artifactFilesystemPersistenceIsRWX" -}}
{{- if and (eq (include "hibou.artifactFilesystemPersistenceEnabled" .) "true") (eq .Values.artifact.filesystem.persistence.accessMode "ReadWriteMany") -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{- define "hibou.artifactUsesBundledSeaweedFS" -}}
{{- if and (eq (include "hibou.artifactBackend" .) "s3") .Values.seaweedfs.enabled (eq (trim .Values.artifact.s3.endpoint) "") -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{- define "hibou.artifactS3Endpoint" -}}
{{- if eq (include "hibou.artifactBackend" .) "s3" -}}
{{- if eq (include "hibou.artifactUsesBundledSeaweedFS" .) "true" -}}
{{- printf "http://%s:8333" (include "hibou.seaweedfsServiceName" .) -}}
{{- else -}}
{{- required "artifact.s3.endpoint must be set when artifact.backend=s3 and bundled SeaweedFS is not in use" .Values.artifact.s3.endpoint -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hibou.artifactS3Bucket" -}}
{{- if eq (include "hibou.artifactUsesBundledSeaweedFS" .) "true" -}}
{{- default .Values.seaweedfs.bucket .Values.artifact.s3.bucket -}}
{{- else -}}
{{- required "artifact.s3.bucket must be set when artifact.backend=s3" .Values.artifact.s3.bucket -}}
{{- end -}}
{{- end -}}

{{- define "hibou.artifactS3CredentialsSecretName" -}}
{{- if eq (include "hibou.artifactUsesBundledSeaweedFS" .) "true" -}}
{{- include "hibou.seaweedfsSecretName" . -}}
{{- else if .Values.artifact.s3.existingSecret -}}
{{- .Values.artifact.s3.existingSecret -}}
{{- else -}}
{{- printf "%s-artifact-s3" (include "hibou.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "hibou.databaseURL" -}}
{{- if .Values.hibou.database.url -}}
{{- .Values.hibou.database.url -}}
{{- else if .Values.cnpg.cluster.enabled -}}
{{/* CNPG: connection details from the generated app secret */}}
{{- else -}}
{{/* Database URL is read from the secret at runtime, not baked into templates */}}
{{- end -}}
{{- end -}}

{{- define "hibou.trivyURL" -}}
{{- if .Values.hibou.trivy.url -}}
{{- .Values.hibou.trivy.url -}}
{{- else if .Values.trivy.enabled -}}
{{- printf "http://%s:4954" (include "hibou.trivyServiceName" .) -}}
{{- else -}}
{{- required "hibou.trivy.url must be set when trivy.enabled=false" .Values.hibou.trivy.url -}}
{{- end -}}
{{- end -}}

{{- define "hibou.baseURL" -}}
{{- if .Values.hibou.baseURL -}}
{{- .Values.hibou.baseURL -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hostname -}}
{{- if .Values.ingress.tls.enabled -}}
{{- printf "https://%s" .Values.ingress.hostname -}}
{{- else -}}
{{- printf "http://%s" .Values.ingress.hostname -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hibou.cnpgClusterName" -}}
{{- printf "%s-pg" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.cnpgServiceName" -}}
{{- printf "%s-pg-rw" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.totalReplicas" -}}
{{- $workerReplicas := 0 -}}
{{- if .Values.hibou.worker.enabled -}}
{{- $workerReplicas = int .Values.hibou.worker.replicas -}}
{{- end -}}
{{- add (int .Values.hibou.replicas) $workerReplicas -}}
{{- end -}}

{{- define "hibou.validateStatelessness" -}}
{{- $totalReplicas := int (include "hibou.totalReplicas" .) -}}
{{- if gt $totalReplicas 1 -}}
  {{- if eq (include "hibou.artifactBackend" .) "filesystem" -}}
    {{- if ne (include "hibou.artifactFilesystemPersistenceIsRWX" .) "true" -}}
      {{- fail "unsafe multi-replica configuration: filesystem artifact storage is single-replica only unless artifact.filesystem.persistence.enabled=true with artifact.filesystem.persistence.accessMode=ReadWriteMany. Enable the RWX PVC option, bundled SeaweedFS, or artifact.backend=s3 with a shared S3-compatible endpoint before scaling Hibou or worker replicas." -}}
    {{- end -}}
  {{- end -}}
  {{- if not .Values.hibou.sessionSecretExistingSecret -}}
    {{- $sessionSecret := trim .Values.hibou.sessionSecret -}}
    {{- if eq $sessionSecret "change-me-in-production" -}}
      {{- fail "unsafe multi-replica configuration: hibou.sessionSecret is set to the shipped default. Use hibou.sessionSecretExistingSecret or set hibou.sessionSecret to a stable random value shared by every replica." -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- $shutdown := .Values.hibou.shutdown -}}
{{- if le (int $shutdown.terminationGracePeriodSeconds) (add (int $shutdown.timeoutSeconds) (int $shutdown.preStopSleepSeconds)) -}}
  {{- fail "hibou.shutdown.terminationGracePeriodSeconds must be greater than hibou.shutdown.timeoutSeconds + hibou.shutdown.preStopSleepSeconds so pods outlive preStop and app drain time." -}}
{{- end -}}
{{- end -}}

{{- define "hibou.podAntiAffinity" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- if $root.Values.hibou.podAntiAffinity.enabled }}
affinity:
  podAntiAffinity:
    {{- if eq $root.Values.hibou.podAntiAffinity.type "hard" }}
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels:
            {{- include "hibou.selectorLabels" $root | nindent 12 }}
            app.kubernetes.io/component: {{ $component }}
        topologyKey: {{ $root.Values.hibou.podAntiAffinity.topologyKey | quote }}
    {{- else }}
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: {{ $root.Values.hibou.podAntiAffinity.weight }}
        podAffinityTerm:
          labelSelector:
            matchLabels:
              {{- include "hibou.selectorLabels" $root | nindent 14 }}
              app.kubernetes.io/component: {{ $component }}
          topologyKey: {{ $root.Values.hibou.podAntiAffinity.topologyKey | quote }}
    {{- end }}
{{- end }}
{{- end -}}

{{/*
Guard the API pod's scratch volume against the clone it would have to hold.

The CVE feed sweep keeps a ~10 MB blobless clone there, which is why scratch is
always mounted and why its default sizeLimit is small. Secret scanning on the
same pod clones whole repositories instead — up to secretScan.maxRepoMB, default
2048 MB — so enabling it without raising the limit gives a volume that fills and
a pod that is evicted. That is the Trivy-DB DiskPressure failure again, and it is
cheaper to refuse the install than to debug it on a node.

Fails rather than raising the limit silently: ephemeral-storage requests decide
where the scheduler can place the pod, so the operator has to see the number.
*/}}
{{- define "hibou.validateScratchForSecretScan" -}}
{{- if .Values.hibou.background.secretScan -}}
{{- $limit := .Values.hibou.scratch.sizeLimit | toString -}}
{{- $value := regexFind "^[0-9]+" $limit | int -}}
{{- $megabytes := 0 -}}
{{- if hasSuffix "Gi" $limit -}}
{{- $megabytes = mul $value 1024 -}}
{{- else if hasSuffix "Mi" $limit -}}
{{- $megabytes = $value -}}
{{- else -}}
{{- fail (printf "hibou.scratch.sizeLimit %q must be expressed in Mi or Gi so it can be checked against the repository clones secret scanning writes there." $limit) -}}
{{- end -}}
{{- $needed := 2048 -}}
{{- if .Values.hibou.secretScan.maxRepoMB -}}
{{- $needed = .Values.hibou.secretScan.maxRepoMB | int -}}
{{- end -}}
{{- if lt $megabytes $needed -}}
{{- fail (printf "hibou.background.secretScan is enabled on the request-serving pod, but hibou.scratch.sizeLimit is %s (%d Mi) and a single repository clone may reach %d Mi. Raise hibou.scratch.sizeLimit and hibou.resources.requests.ephemeral-storage together, or run secret scanning on a worker (hibou.worker.enabled with hibou.worker.background.secretScan)." $limit $megabytes $needed) -}}
{{- end -}}
{{- end -}}
{{- end -}}
