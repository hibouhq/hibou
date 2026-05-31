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
