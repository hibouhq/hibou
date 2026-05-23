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
{{- printf "%s-postgresql" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.trivyServiceName" -}}
{{- printf "%s-trivy" (include "hibou.fullname" .) -}}
{{- end -}}

{{- define "hibou.databaseURL" -}}
{{- if .Values.hibou.databaseURL -}}
{{- .Values.hibou.databaseURL -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "hibou.postgresqlServiceName" .) .Values.postgresql.auth.database -}}
{{- else -}}
{{- required "hibou.databaseURL must be set when postgresql.enabled=false" .Values.hibou.databaseURL -}}
{{- end -}}
{{- end -}}

{{- define "hibou.trivyURL" -}}
{{- if .Values.hibou.trivyURL -}}
{{- .Values.hibou.trivyURL -}}
{{- else if .Values.trivy.enabled -}}
{{- printf "http://%s:4954" (include "hibou.trivyServiceName" .) -}}
{{- else -}}
{{- required "hibou.trivyURL must be set when trivy.enabled=false" .Values.hibou.trivyURL -}}
{{- end -}}
{{- end -}}