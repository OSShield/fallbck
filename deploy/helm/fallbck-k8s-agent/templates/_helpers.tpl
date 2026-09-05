{{- define "fallbck-k8s-agent.name" -}}
{{ .Chart.Name }}
{{- end }}
{{- define "fallbck-k8s-agent.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "fallbck-k8s-agent.workerImage" -}}
{{- if .Values.worker.image }}{{ .Values.worker.image }}{{ else }}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{ end -}}
{{- end }}
