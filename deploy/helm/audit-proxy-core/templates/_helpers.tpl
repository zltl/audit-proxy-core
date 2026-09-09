{{/*
Expand the name of the chart.
*/}}
{{- define "audit-proxy-core.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "audit-proxy-core.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "audit-proxy-core.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "audit-proxy-core.labels" -}}
helm.sh/chart: {{ include "audit-proxy-core.chart" . }}
{{ include "audit-proxy-core.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "audit-proxy-core.selectorLabels" -}}
app.kubernetes.io/name: {{ include "audit-proxy-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "audit-proxy-core.serviceAccountName" -}}
{{- if .Values.serviceAccount }}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "audit-proxy-core.fullname" . }}
{{- end }}
{{- else }}
{{- include "audit-proxy-core.fullname" . }}
{{- end }}
{{- end }}

{{/*
Return the image tag (defaults to appVersion).
*/}}
{{- define "audit-proxy-core.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Return the full image reference.
*/}}
{{- define "audit-proxy-core.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "audit-proxy-core.imageTag" .) }}
{{- end }}

{{/*
Data-plane selector labels.
*/}}
{{- define "audit-proxy-core.dataPlane.selectorLabels" -}}
{{ include "audit-proxy-core.selectorLabels" . }}
app.kubernetes.io/component: data-plane
{{- end }}

{{/*
Control-plane selector labels.
*/}}
{{- define "audit-proxy-core.controlPlane.selectorLabels" -}}
{{ include "audit-proxy-core.selectorLabels" . }}
app.kubernetes.io/component: control-plane
{{- end }}
