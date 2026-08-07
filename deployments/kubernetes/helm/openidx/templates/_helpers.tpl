{{/*
Expand the name of the chart.
*/}}
{{- define "openidx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "openidx.fullname" -}}
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
{{- define "openidx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "openidx.labels" -}}
helm.sh/chart: {{ include "openidx.chart" . }}
{{ include "openidx.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "openidx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openidx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "openidx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "openidx.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Zero-downtime pod termination.

Kubernetes removes a Pod from Service endpoints and sends SIGTERM at the same
time, and those two things race across the cluster. The application already
drains correctly (internal/server/graceful.go), but if it exits the instant it
receives SIGTERM, kube-proxy on some nodes may still be forwarding to it — the
caller sees a connection reset. That is the usual cause of 502s during an
otherwise healthy rolling update.

preStop simply waits, doing nothing, so endpoint removal wins the race before
the container starts shutting down. terminationGracePeriodSeconds must exceed
the preStop delay plus the application's own drain window, otherwise Kubernetes
sends SIGKILL mid-drain and cuts live requests.

Usage: {{- include "openidx.gracefulTermination" . | nindent 6 }}  (pod spec level)
*/}}
{{- define "openidx.gracefulTermination" -}}
{{- $g := .Values.gracefulTermination | default dict -}}
{{- if ne (dig "enabled" true $g) false }}
terminationGracePeriodSeconds: {{ dig "gracePeriodSeconds" 45 $g }}
{{- end }}
{{- end }}

{{/*
preStop lifecycle hook, applied at container level.

Kept separate from the pod-level setting above because Kubernetes puts them in
different places in the spec.
*/}}
{{- define "openidx.preStopHook" -}}
{{- $g := .Values.gracefulTermination | default dict -}}
{{- if ne (dig "enabled" true $g) false }}
lifecycle:
  preStop:
    exec:
      # Sleep only. The application's own graceful shutdown does the draining;
      # this delay exists purely so endpoint removal propagates first.
      command: ["/bin/sh", "-c", "sleep {{ dig "preStopSeconds" 5 $g }}"]
{{- end }}
{{- end }}

{{/*
Spread replicas across failure domains.

podAntiAffinity (already used here) keeps replicas off the same node, which
survives a node failure. It does not, on its own, stop every replica landing in
one availability zone — so an AZ outage would still take the whole service down.
This constraint spreads across zones as well.

whenUnsatisfiable is ScheduleAnyway on purpose: DoNotSchedule would leave pods
Pending on a single-zone cluster, which trades an availability improvement for
an outage. A best-effort spread is the right default; operators who run
multi-zone and want the hard guarantee can set it to DoNotSchedule.

Usage: {{- include "openidx.topologySpread" (dict "ctx" . "component" "identity-service") | nindent 6 }}
*/}}
{{- define "openidx.topologySpread" -}}
{{- $ctx := .ctx -}}
{{- $t := $ctx.Values.topologySpread | default dict -}}
{{- if ne (dig "enabled" true $t) false }}
topologySpreadConstraints:
  - maxSkew: {{ dig "maxSkew" 1 $t }}
    topologyKey: {{ dig "topologyKey" "topology.kubernetes.io/zone" $t }}
    whenUnsatisfiable: {{ dig "whenUnsatisfiable" "ScheduleAnyway" $t }}
    labelSelector:
      matchLabels:
        {{- include "openidx.selectorLabels" $ctx | nindent 8 }}
        app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end }}

{{/*
Rolling update strategy.

Kubernetes defaults to maxUnavailable=25%, which means a rollout may take a
quarter of the fleet out of service before any replacement is Ready. Under load
that shows up as elevated latency or shed traffic during an ordinary deploy.

maxUnavailable: 0 with maxSurge: 1 inverts that: a new pod must become Ready
before an old one is removed, so capacity never dips below the declared replica
count. The cost is one extra pod's worth of resources for the duration of the
rollout, which is the right trade for an always-on service.

Usage: {{- include "openidx.rollingStrategy" . | nindent 2 }}  (deployment spec level)
*/}}
{{- define "openidx.rollingStrategy" -}}
{{- $s := .Values.rollingUpdate | default dict -}}
{{- if ne (dig "enabled" true $s) false }}
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: {{ dig "maxUnavailable" 0 $s }}
    maxSurge: {{ dig "maxSurge" 1 $s }}
{{- end }}
{{- end }}
