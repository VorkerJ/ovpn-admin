{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $r := .MergedPushRoutes }}
push "route {{ $r.Address }} {{ $r.Mask }}" # {{ $r.Source }}
{{- end }}
