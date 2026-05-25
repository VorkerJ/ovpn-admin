{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $route := .CustomRoutes }}
{{- if eq $route.Kind "domain" }}
{{- range $ip := $route.ResolvedIPs }}
push "route {{ $ip }} 255.255.255.255" # __user_domain__:{{ $route.Domain }} {{ $route.Description }}
{{- end }}
{{- else }}
push "route {{ $route.Address }} {{ $route.Mask }}" # {{ $route.Description }}
{{- end }}
{{- end }}
{{- range $route := .CommonRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}" # __common__:{{ $route.Tag }} {{ $route.Description }}
{{- end }}
