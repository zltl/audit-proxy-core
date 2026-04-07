{{/*
Expand the name of the chart.
*/}}
{{- define "ssh-proxy-core.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ssh-proxy-core.fullname" -}}
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
{{- define "ssh-proxy-core.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "ssh-proxy-core.labels" -}}
helm.sh/chart: {{ include "ssh-proxy-core.chart" . }}
{{ include "ssh-proxy-core.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "ssh-proxy-core.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssh-proxy-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "ssh-proxy-core.serviceAccountName" -}}
{{- if .Values.serviceAccount }}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "ssh-proxy-core.fullname" . }}
{{- end }}
{{- else }}
{{- include "ssh-proxy-core.fullname" . }}
{{- end }}
{{- end }}

{{/*
Return the image tag (defaults to appVersion).
*/}}
{{- define "ssh-proxy-core.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Return the full image reference.
*/}}
{{- define "ssh-proxy-core.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "ssh-proxy-core.imageTag" .) }}
{{- end }}

{{/*
Data-plane selector labels.
*/}}
{{- define "ssh-proxy-core.dataPlane.selectorLabels" -}}
{{ include "ssh-proxy-core.selectorLabels" . }}
app.kubernetes.io/component: data-plane
{{- end }}

{{/*
Control-plane selector labels.
*/}}
{{- define "ssh-proxy-core.controlPlane.selectorLabels" -}}
{{ include "ssh-proxy-core.selectorLabels" . }}
app.kubernetes.io/component: control-plane
{{- end }}
