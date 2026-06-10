package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

func (oAdmin *OvpnAdmin) getCcdTemplate() *template.Template {
	if *ccdTemplatePath != "" {
		return template.Must(template.ParseFiles(*ccdTemplatePath))
	} else {
		data, err := fs.ReadFile(oAdmin.templates, "ccd.tpl")
		if err != nil {
			log.Errorf("ccdTpl not found in embedded templates: %v", err)
		}
		return template.Must(template.New("ccd").Parse(string(data)))
	}
}

// reservedCcdMarkers are the comment tokens parseCcd uses to classify push
// lines. They must never appear in a user-supplied description, otherwise a
// crafted description could be confused for control state on round-trip.
// Validation rejects them at write time; parseCcd additionally anchors on the
// directive shape so even a pre-existing file can't forge state.
var reservedCcdMarkers = []string{
	"__redirect_gateway__", "__exclusion_user__", "__exclusion_global__",
	"__common__", "__user_domain__",
}

func descriptionHasReservedMarker(desc string) bool {
	for _, m := range reservedCcdMarkers {
		if strings.Contains(desc, m) {
			return true
		}
	}
	return false
}

// splitDirectiveComment splits a CCD line into the directive part (before the
// first " # ") and the comment (after it, leading "# " stripped). When there
// is no comment, comment is "".
func splitDirectiveComment(line string) (directive, comment string) {
	if i := strings.Index(line, " # "); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+3:])
	}
	return strings.TrimSpace(line), ""
}

// quotedPayload returns the text between the first and last double-quote of s
// — i.e. the body of a `push "..."` directive. Returns "" when s isn't quoted.
func quotedPayload(s string) string {
	first := strings.Index(s, "\"")
	last := strings.LastIndex(s, "\"")
	if first < 0 || last <= first {
		return ""
	}
	return s[first+1 : last]
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}
	ccd.RedirectGatewayExclusions = []Subnet{}

	var txtLinesArray []string
	ccdContent := oAdmin.store.GetCcd(ccd.User)
	if ccdContent != "" {
		txtLinesArray = strings.Split(ccdContent, "\n")
	}

	// Per-user domain routes are written as multiple push lines with
	// `# __user_domain__:DOMAIN` marker — collapse them back into one entry.
	domainEntries := map[string]*ccdRoute{}
	domainOrder := []string{}
	var ipRoutes []ccdRoute

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(str[0], "ifconfig-push"):
			ccd.ClientAddress = str[1]
		case strings.HasPrefix(str[0], "push"):
			// Split the directive from its trailing "# ..." comment and trust a
			// marker ONLY when the DIRECTIVE itself has the matching shape.
			// Substring-scanning the whole line (the old approach) let a
			// user-supplied route description containing a marker string (e.g.
			// "__redirect_gateway__" or "__exclusion_user__ ...") forge control
			// state on round-trip: parseCcd would misclassify the route, drop
			// it, and persist the forged exclusion / full-tunnel flag on the
			// next write. The directive shape (`redirect-gateway` vs `route`
			// vs `route ... net_gateway`) can only come from our own renderer,
			// so anchoring on it closes that confusion. Legit lines are
			// unchanged — they already have the correct shape.
			directive, comment := splitDirectiveComment(v)
			pf := strings.Fields(quotedPayload(directive))
			if len(pf) == 0 {
				continue
			}

			// `redirect-gateway def1` — only when the directive literally is it.
			if pf[0] == "redirect-gateway" && strings.HasPrefix(comment, "__redirect_gateway__") {
				ccd.RedirectGateway = true
				continue
			}
			// Everything else we recognise is a `route ...` directive.
			if pf[0] != "route" || len(pf) < 3 {
				continue // unknown / unsupported push directive — ignore
			}
			addr, mask := pf[1], pf[2]
			isNetGateway := len(pf) >= 4 && pf[3] == "net_gateway"

			// Exclusions: `route ADDR MASK net_gateway`. Global ones are rebuilt
			// from ServerConfig at render time (swallow on round-trip); per-user
			// ones round-trip into the editable list. A net_gateway route with
			// no recognised marker is also dropped — it can only have come from
			// our own render and exclusions are always rebuilt, so we never keep
			// it as a CustomRoute.
			if isNetGateway {
				if strings.HasPrefix(comment, "__exclusion_user__") {
					desc := strings.TrimSpace(strings.TrimPrefix(comment, "__exclusion_user__"))
					ccd.RedirectGatewayExclusions = append(ccd.RedirectGatewayExclusions, Subnet{
						Address: addr, Mask: mask, Description: desc,
					})
				}
				continue
			}

			// Common routes are rebuilt from the Common Routes store at render
			// time — swallow on round-trip.
			if strings.HasPrefix(comment, "__common__:") {
				continue
			}

			// Per-user domain routes: collapse the multiple resolved-IP push
			// lines back into a single domain entry.
			if strings.HasPrefix(comment, "__user_domain__:") {
				rest := strings.TrimSpace(strings.TrimPrefix(comment, "__user_domain__:"))
				fields := strings.Fields(rest)
				if len(fields) == 0 {
					continue
				}
				domain := fields[0]
				description := strings.TrimSpace(strings.Join(fields[1:], " "))
				entry, exists := domainEntries[domain]
				if !exists {
					entry = &ccdRoute{
						Kind:        "domain",
						Domain:      domain,
						Description: description,
					}
					domainEntries[domain] = entry
					domainOrder = append(domainOrder, domain)
				}
				entry.ResolvedIPs = append(entry.ResolvedIPs, addr)
				continue
			}

			// Plain per-user IP route. The comment is its free-text description.
			ipRoutes = append(ipRoutes, ccdRoute{
				Kind:        "ip",
				Address:     addr,
				Mask:        mask,
				Description: comment,
			})
		}
	}

	ccd.CustomRoutes = append(ccd.CustomRoutes, ipRoutes...)
	for _, d := range domainOrder {
		ccd.CustomRoutes = append(ccd.CustomRoutes, *domainEntries[d])
	}
	return ccd
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd, commonExpanded []ccdCommonRoute) (bool, string) {
	ccdValid, err := oAdmin.validateCcd(ccd)
	if err != "" {
		return false, err
	}
	if !ccdValid {
		return false, "something goes wrong"
	}

	ccd.CommonRoutes = commonExpanded
	// Dedupe so duplicate IPs (typical when several domains resolve to
	// overlapping CDN endpoints — google.com, youtube.com, googlevideo.com
	// often share the same Fastly/Google front-end IPs) emit a single
	// "push route X Y" line. Without this the Windows OpenVPN GUI fills
	// up with "route addition failed because route exists" spam and
	// PUSH_REPLY grows past its 1k limit at scale.
	ccd.MergedPushRoutes = mergePushRoutes(ccd.CustomRoutes, ccd.CommonRoutes)

	// Build the union of global default exclusions and per-user extras.
	// Globals come from ServerConfig at render time (not stored in the CCD
	// file), so changing the global list rerenders without touching users.
	// When the server-wide RedirectGateway flag is on, treat every user as
	// full-tunnel even if their per-user flag is off — matches the
	// historical semantics of the global toggle as a "force everyone" knob.
	if oAdmin.serverConfigStore != nil {
		cfg := oAdmin.serverConfigStore.snapshot()
		if cfg.RedirectGateway {
			ccd.RedirectGateway = true
		}
		ccd.MergedExclusions = mergeExclusions(cfg.RedirectGatewayExclusions, ccd.RedirectGatewayExclusions)
	} else {
		ccd.MergedExclusions = mergeExclusions(nil, ccd.RedirectGatewayExclusions)
	}

	t := oAdmin.getCcdTemplate()
	var tmp bytes.Buffer
	if err := t.Execute(&tmp, ccd); err != nil {
		log.Error(err)
		return false, "template render failed"
	}

	if err := oAdmin.store.SaveCcd(ccd.User, tmp.Bytes()); err != nil {
		log.Errorf("modifyCcd: SaveCcd(): %v", err)
		return false, "write failed"
	}
	return true, "ccd updated successfully"
}

// pushRoute is the unique row emitted into the rendered CCD. Source is
// a human-readable comment composed of every (domain, tag) that asked
// for this IP — useful when an operator greps the file for why a route
// is there.
type pushRoute struct {
	Address string
	Mask    string
	Source  string
}

// mergePushRoutes walks every per-user route + every expanded common
// route and returns one pushRoute per unique (Address, Mask) pair.
// Domain routes expand to their resolved IP set; the original list
// order is preserved so the file stays diff-friendly between renders.
// mergeExclusions walks the global + per-user exclusion lists and returns
// one renderedExclusion per unique (Address, Mask) pair. The Source field
// carries the origin marker so parseCcd can route per-user entries back
// to Ccd.RedirectGatewayExclusions while ignoring global ones (those are
// always re-read from ServerConfig at render time).
//
// Order: globals first (deterministic for diff-friendliness), then per-user
// extras. A duplicate (e.g. user re-adds 192.168.0.0/16 which is already
// global) is collapsed onto the first occurrence with a combined source
// comment, just like mergePushRoutes does for routes.
func mergeExclusions(global, user []Subnet) []renderedExclusion {
	type key struct{ a, m string }
	seen := map[key]int{}
	out := []renderedExclusion{}
	add := func(s Subnet, marker string) {
		if s.Address == "" || s.Mask == "" {
			return
		}
		k := key{s.Address, s.Mask}
		src := marker
		if d := strings.TrimSpace(s.Description); d != "" {
			src = marker + " " + d
		}
		if idx, ok := seen[k]; ok {
			if !strings.Contains(out[idx].Source, marker) {
				out[idx].Source += "," + src
			}
			return
		}
		seen[k] = len(out)
		out = append(out, renderedExclusion{Address: s.Address, Mask: s.Mask, Source: src})
	}
	for _, s := range global {
		add(s, "__exclusion_global__")
	}
	for _, s := range user {
		add(s, "__exclusion_user__")
	}
	return out
}

func mergePushRoutes(custom []ccdRoute, common []ccdCommonRoute) []pushRoute {
	type srcKey struct{ a, m string }
	seen := map[srcKey]int{} // key → index into out
	out := []pushRoute{}
	add := func(addr, mask, src string) {
		if addr == "" || mask == "" {
			return
		}
		k := srcKey{addr, mask}
		if idx, ok := seen[k]; ok {
			// Append the new source so the comment lists every domain /
			// tag that referenced this IP.
			if !strings.Contains(out[idx].Source, src) {
				out[idx].Source += "," + src
			}
			return
		}
		seen[k] = len(out)
		out = append(out, pushRoute{Address: addr, Mask: mask, Source: src})
	}

	withDesc := func(prefix, desc string) string {
		desc = strings.TrimSpace(desc)
		if desc == "" {
			return prefix
		}
		return prefix + " " + desc
	}
	for _, r := range custom {
		switch r.Kind {
		case "domain":
			for _, ip := range r.ResolvedIPs {
				add(ip, "255.255.255.255", withDesc("__user_domain__:"+r.Domain, r.Description))
			}
		default: // "ip" (legacy: empty Kind also means ip)
			add(r.Address, r.Mask, r.Description)
		}
	}
	for _, r := range common {
		add(r.Address, r.Mask, withDesc("__common__:"+r.Tag, r.Description))
	}
	return out
}

func (oAdmin *OvpnAdmin) rerenderAllCcds(commonExpanded []ccdCommonRoute) {
	ccdMu.Lock()
	defer ccdMu.Unlock()

	start := time.Now()
	count := 0
	changedUsers := []string{}
	for _, u := range oAdmin.snapshotClients() {
		if u.AccountStatus != "Active" {
			continue
		}
		ccd := oAdmin.getCcd(u.Identity)
		ok, msg := oAdmin.modifyCcd(ccd, commonExpanded)
		if !ok {
			log.Warnf("rerenderAllCcds: %s: %s", u.Identity, msg)
			continue
		}
		count++
		changedUsers = append(changedUsers, u.Identity)
	}
	log.Infof("rerenderAllCcds: rerendered %d CCDs in %s", count, time.Since(start))
	// Kick affected users so their next reconnect picks up the new push
	// directives. CCD changes only apply at connect time; without a kick
	// the user keeps the stale routes until they happen to reconnect on
	// their own.
	oAdmin.kickUsersAfterCcdChange(changedUsers)
}

// kickUsersAfterCcdChange disconnects each listed user from every mgmt
// interface we know about. The user's OpenVPN client auto-reconnects
// (typically within 5 seconds) and receives the freshly-written CCD.
// Errors are logged but never fatal — a missing kill just means the
// user wasn't connected on that server.
func (oAdmin *OvpnAdmin) kickUsersAfterCcdChange(users []string) {
	if len(users) == 0 {
		return
	}
	for _, cn := range users {
		for srv := range oAdmin.mgmtInterfaces {
			oAdmin.mgmtKillUserConnection(cn, srv)
		}
	}
	log.Infof("kickUsersAfterCcdChange: signalled %d user(s) to reconnect", len(users))
}

func (oAdmin *OvpnAdmin) runCommonRoutesScheduler() {
	ctx := context.Background()

	runOnce := func() {
		// 1) refresh global common-routes domains
		current := oAdmin.commonRoutes.snapshot()
		hasDomain := false
		for _, r := range current.Routes {
			if r.Kind == "domain" {
				hasDomain = true
				break
			}
		}
		if hasDomain {
			updated, changed, okCount, failed := refreshAllDomains(ctx, current, time.Now())
			oAdmin.commonRoutes.replace(updated)
			if err := oAdmin.persistCommonRoutes(updated); err != nil {
				log.Errorf("scheduler persist: %v", err)
			}
			log.Infof("common-routes scheduler: resolved=%d failed=%d changed=%v", okCount, failed, changed)
			if changed {
				oAdmin.rerenderAllCcds(expandCommonRoutes(updated))
			}
		}

		// 2) refresh per-user CCD domain routes
		oAdmin.refreshAllUserDomains(ctx)
	}

	runOnce()

	// Re-read interval each tick so a UI change takes effect at the next
	// fire without restarting the process. interval==0 pauses the loop
	// entirely; admin can resume by saving a non-zero value.
	for {
		interval := 24 * time.Hour
		if oAdmin.serverConfigStore != nil {
			h := oAdmin.serverConfigStore.snapshot().DomainRefreshIntervalHours
			if h > 0 {
				interval = time.Duration(h) * time.Hour
			} else if h < 0 {
				// negative means "disabled"; wait an hour then re-check
				interval = time.Hour
			}
		}
		time.Sleep(interval)
		// Skip the refresh body when the admin has disabled it; only the
		// re-poll loop above keeps spinning.
		if oAdmin.serverConfigStore != nil && oAdmin.serverConfigStore.snapshot().DomainRefreshIntervalHours < 0 {
			continue
		}
		runOnce()
	}
}

// refreshAllUserDomains re-resolves all per-user CCD domain routes and rewrites
// CCD files for users whose resolved IP set changed.
func (oAdmin *OvpnAdmin) refreshAllUserDomains(ctx context.Context) {
	ccdMu.Lock()
	defer ccdMu.Unlock()

	commonExpanded := []ccdCommonRoute{}
	if oAdmin.commonRoutes != nil {
		commonExpanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
	}

	changedUsers := []string{}
	for _, u := range oAdmin.snapshotClients() {
		if u.AccountStatus != "Active" {
			continue
		}
		ccd := oAdmin.getCcd(u.Identity)
		hasDomain := false
		for _, r := range ccd.CustomRoutes {
			if r.Kind == "domain" {
				hasDomain = true
				break
			}
		}
		if !hasDomain {
			continue
		}
		changed := false
		for i, route := range ccd.CustomRoutes {
			if route.Kind != "domain" || route.Domain == "" {
				continue
			}
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, err := domainResolver(resolveCtx, route.Domain)
			cancel()
			ccd.CustomRoutes[i].LastResolveAt = time.Now().UTC().Format(time.RFC3339)
			if err != nil {
				ccd.CustomRoutes[i].LastResolveErr = err.Error()
				continue
			}
			ccd.CustomRoutes[i].LastResolveErr = ""
			if !sameIPSet(route.ResolvedIPs, ips) {
				ccd.CustomRoutes[i].ResolvedIPs = ips
				changed = true
			}
		}
		if changed {
			if ok, msg := oAdmin.modifyCcd(ccd, commonExpanded); !ok {
				log.Warnf("refreshAllUserDomains: %s: %s", u.Identity, msg)
				continue
			}
			changedUsers = append(changedUsers, u.Identity)
		}
	}
	// Only kick when IPs actually shifted — otherwise the periodic 24h
	// refresh would tear down every connection daily for no reason.
	oAdmin.kickUsersAfterCcdChange(changedUsers)
}

func (oAdmin *OvpnAdmin) validateCcd(ccd Ccd) (bool, string) {

	ccdErr := ""

	if ccd.ClientAddress != "dynamic" {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !oAdmin.checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	for _, route := range ccd.CustomRoutes {
		if strings.ContainsAny(route.Description, "\n\r") {
			return false, "route description must not contain newlines"
		}
		if strings.Contains(route.Description, `"`) {
			return false, "route description must not contain double quotes"
		}
		if descriptionHasReservedMarker(route.Description) {
			return false, "route description must not contain reserved markers (__redirect_gateway__, __exclusion_*, __common__, __user_domain__)"
		}
		if len(route.Description) > 200 {
			return false, "route description too long (max 200 chars)"
		}
		switch route.Kind {
		case "domain":
			if route.Domain == "" {
				ccdErr = "CustomRoute.Domain must be non-empty for kind=domain"
				return false, ccdErr
			}
			if !domainRegexp.MatchString(route.Domain) {
				ccdErr = fmt.Sprintf("CustomRoute.Domain %q is not a valid hostname", route.Domain)
				return false, ccdErr
			}
		case "ip", "":
			if net.ParseIP(route.Address) == nil {
				ccdErr = fmt.Sprintf("CustomRoute.Address %q must be a valid IP address", route.Address)
				return false, ccdErr
			}
			if net.ParseIP(route.Mask) == nil {
				ccdErr = fmt.Sprintf("CustomRoute.Mask %q must be a valid IP address", route.Mask)
				return false, ccdErr
			}
		default:
			ccdErr = fmt.Sprintf("CustomRoute.Kind %q is invalid (expected ip|domain)", route.Kind)
			return false, ccdErr
		}
	}

	for i, e := range ccd.RedirectGatewayExclusions {
		if err := validateSubnet(e); err != nil {
			ccdErr = fmt.Sprintf("RedirectGatewayExclusions[%d]: %v", i, err)
			return false, ccdErr
		}
	}

	return true, ccdErr
}

func (oAdmin *OvpnAdmin) commonRoutesSnapshot() CommonRoutesConfig {
	if oAdmin.commonRoutes == nil {
		return CommonRoutesConfig{}
	}
	return oAdmin.commonRoutes.snapshot()
}

// getCcd is a thin wrapper around parseCcd kept for call-site readability
// (most callers want "give me this user's CCD" not "parse this user's CCD"
// — the distinction matters when we one day cache parsed results).
func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	return oAdmin.parseCcd(username)
}

// HTTP method check is enforced by requireMethod middleware at route
// registration time; do not re-check it inside handlers.

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}
	ccd, _ := json.Marshal(oAdmin.getCcd(req.Username))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var ccd Ccd
	if r.Body == nil {
		writeJSONError(w, http.StatusBadRequest, "Please send a request body")
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
	}
	if err := validateUsername(ccd.User); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	// For per-user domain routes: preserve resolved IPs from existing CCD when the
	// domain itself is unchanged; resolve synchronously for new/changed domains.
	existingCcd := oAdmin.getCcd(ccd.User)
	existingDomain := make(map[string]ccdRoute)
	for _, r := range existingCcd.CustomRoutes {
		if r.Kind == "domain" {
			existingDomain[r.Domain] = r
		}
	}
	for i, route := range ccd.CustomRoutes {
		if route.Kind != "domain" || route.Domain == "" {
			continue
		}
		if len(route.ResolvedIPs) > 0 {
			continue // client preserved them
		}
		if existing, ok := existingDomain[route.Domain]; ok && len(existing.ResolvedIPs) > 0 {
			ccd.CustomRoutes[i].ResolvedIPs = existing.ResolvedIPs
			ccd.CustomRoutes[i].LastResolveAt = existing.LastResolveAt
			ccd.CustomRoutes[i].LastResolveErr = existing.LastResolveErr
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		ips, lerr := domainResolver(ctx, route.Domain)
		cancel()
		ccd.CustomRoutes[i].LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if lerr != nil {
			ccd.CustomRoutes[i].LastResolveErr = lerr.Error()
		} else {
			ccd.CustomRoutes[i].ResolvedIPs = ips
			ccd.CustomRoutes[i].LastResolveErr = ""
		}
	}

	var expanded []ccdCommonRoute
	if oAdmin.commonRoutes != nil {
		expanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd, expanded)

	if ccdApplied {
		// Триггер пересчёта firewall-правил для этого CN
		if oAdmin.firewall != nil {
			oAdmin.firewall.push(fwEvent{Kind: EvUserChanged, CN: ccd.User})
		}
		// Kick the user so they reconnect and pick up the new push lines.
		oAdmin.kickUsersAfterCcdChange([]string{ccd.User})
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

// userCcdImportHandler POST /api/user/ccd/import.
// Body: { "username": "...", "text": "<lines>" }.
// Parses every line, appends valid ones to the user's CCD, skips
// duplicates against existing per-user routes AND within the payload,
// returns parse errors with line numbers.
func (oAdmin *OvpnAdmin) userCcdImportHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req struct {
		Username string `json:"username"`
		Text     string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	parsed, errs := parseImportText(req.Text)

	ccd := oAdmin.getCcd(req.Username)
	// Dedup vs existing per-user routes.
	existing := map[string]struct{}{}
	for _, e := range ccd.CustomRoutes {
		var k string
		if e.Kind == "domain" {
			k = "d:" + strings.ToLower(strings.TrimSpace(e.Domain))
		} else {
			k = "i:" + e.Address + "/" + e.Mask
		}
		existing[k] = struct{}{}
	}

	added := []ImportedRoute{}
	skipped := []ImportedRoute{}
	for _, p := range parsed {
		key := routeDedupKey(p)
		if _, dup := existing[key]; dup {
			skipped = append(skipped, p)
			continue
		}
		entry := ccdRoute{Kind: p.Kind, Domain: p.Domain}
		if p.Kind == "ip" {
			entry.Address = p.Address
			entry.Mask = p.Mask
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			ips, derr := domainResolver(ctx, entry.Domain)
			cancel()
			entry.LastResolveAt = time.Now().UTC().Format(time.RFC3339)
			if derr != nil {
				entry.LastResolveErr = derr.Error()
			} else {
				entry.ResolvedIPs = ips
			}
		}
		ccd.CustomRoutes = append(ccd.CustomRoutes, entry)
		existing[key] = struct{}{}
		added = append(added, p)
	}

	if len(added) == 0 {
		writeJSON(w, http.StatusOK, ImportResult{Added: added, Skipped: skipped, Errors: errs})
		return
	}

	var expanded []ccdCommonRoute
	if oAdmin.commonRoutes != nil {
		expanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
	}
	if ok, msg := oAdmin.modifyCcd(ccd, expanded); !ok {
		// modifyCcd ran the per-route validators and refused the merged
		// set — return what we tried so the user can see and retry.
		errs = append(errs, ImportLineError{Reason: "ccd validation failed: " + msg})
		writeJSON(w, http.StatusUnprocessableEntity, ImportResult{Added: nil, Skipped: skipped, Errors: errs})
		return
	}
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvUserChanged, CN: req.Username})
	}
	oAdmin.kickUsersAfterCcdChange([]string{req.Username})
	writeJSON(w, http.StatusOK, ImportResult{Added: added, Skipped: skipped, Errors: errs})
}

// userCcdRefreshHandler re-resolves every domain route in the named user's
// CCD with the current resolver, rewrites the CCD if any IP set changed,
// and kicks the user so their next reconnect carries the refreshed push
// directives. Same auth gate as userApplyCcdHandler.
func (oAdmin *OvpnAdmin) userCcdRefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	ccd := oAdmin.getCcd(req.Username)
	changed := false
	resolved := 0
	failed := 0
	for i, route := range ccd.CustomRoutes {
		if route.Kind != "domain" || route.Domain == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		ips, err := domainResolver(ctx, route.Domain)
		cancel()
		ccd.CustomRoutes[i].LastResolveAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			ccd.CustomRoutes[i].LastResolveErr = err.Error()
			failed++
			continue
		}
		ccd.CustomRoutes[i].LastResolveErr = ""
		resolved++
		if !sameIPSet(route.ResolvedIPs, ips) {
			ccd.CustomRoutes[i].ResolvedIPs = ips
			changed = true
		}
	}

	if !changed {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"changed":  false,
			"resolved": resolved,
			"failed":   failed,
		})
		return
	}

	var expanded []ccdCommonRoute
	if oAdmin.commonRoutes != nil {
		expanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
	}
	if ok, msg := oAdmin.modifyCcd(ccd, expanded); !ok {
		writeJSONError(w, http.StatusUnprocessableEntity, msg)
		return
	}
	if oAdmin.firewall != nil {
		oAdmin.firewall.push(fwEvent{Kind: EvUserChanged, CN: req.Username})
	}
	oAdmin.kickUsersAfterCcdChange([]string{req.Username})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"changed":  true,
		"resolved": resolved,
		"failed":   failed,
	})
}
