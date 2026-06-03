{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- if .RedirectGateway }}
push "redirect-gateway def1" # __redirect_gateway__
{{- range $e := .MergedExclusions }}
push "route {{ $e.Address }} {{ $e.Mask }} net_gateway" # {{ $e.Source }}
{{- end }}
{{- end }}
{{- range $r := .MergedPushRoutes }}
push "route {{ $r.Address }} {{ $r.Mask }}" # {{ $r.Source }}
{{- end }}
