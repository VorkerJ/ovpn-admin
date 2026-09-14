{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} {{ .ClientMask }}
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
{{- /* Audit F30: persist the user's OWN full-tunnel intent independently of the
     rendered redirect-gateway push, so a global-off returns them to their choice.
     `#` lines are comments OpenVPN ignores; parseCcd reads them back. */}}
# __user_redirect__:{{ if .UserRedirectGateway }}on{{ else }}off{{ end }}
{{- /* Audit F31: declare every domain route even when it currently resolves to
     zero IPs (transient DNS failure), so the route survives a save→parse round
     trip and the scheduler can retry it later. */}}
{{- range $r := .CustomRoutes }}
{{- if eq $r.Kind "domain" }}
# __user_domain_decl__:{{ $r.Domain }}{{ if $r.Description }} {{ $r.Description }}{{ end }}
{{- end }}
{{- end }}
