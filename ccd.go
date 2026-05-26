package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
		ccdTpl, ccdTplErr := oAdmin.templates.FindString("ccd.tpl")
		if ccdTplErr != nil {
			log.Errorf("ccdTpl not found in templates box")
		}
		return template.Must(template.New("ccd").Parse(ccdTpl))
	}
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

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
			if strings.Contains(v, "# __common__:") {
				continue
			}
			if idx := strings.Index(v, "# __user_domain__:"); idx >= 0 {
				comment := strings.TrimSpace(v[idx+len("# __user_domain__:"):])
				fields := strings.Fields(comment)
				if len(fields) == 0 {
					continue
				}
				domain := fields[0]
				description := strings.TrimSpace(strings.Join(fields[1:], " "))
				ip := strings.Trim(str[2], "\"")
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
				entry.ResolvedIPs = append(entry.ResolvedIPs, ip)
				continue
			}
			ipRoutes = append(ipRoutes, ccdRoute{
				Kind:        "ip",
				Address:     strings.Trim(str[2], "\""),
				Mask:        strings.Trim(str[3], "\""),
				Description: strings.Trim(strings.Join(str[4:], ""), "#"),
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

func (oAdmin *OvpnAdmin) rerenderAllCcds(commonExpanded []ccdCommonRoute) {
	ccdMu.Lock()
	defer ccdMu.Unlock()

	start := time.Now()
	count := 0
	for _, u := range oAdmin.clients {
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
	}
	log.Infof("rerenderAllCcds: rerendered %d CCDs in %s", count, time.Since(start))
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

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
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

	for _, u := range oAdmin.clients {
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
			}
		}
	}
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

	return true, ccdErr
}

func (oAdmin *OvpnAdmin) commonRoutesSnapshot() CommonRoutesConfig {
	if oAdmin.commonRoutes == nil {
		return CommonRoutesConfig{}
	}
	return oAdmin.commonRoutes.snapshot()
}

func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	ccd = oAdmin.parseCcd(username)

	return ccd
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, `{"error":"invalid username"}`, http.StatusBadRequest)
		return
	}
	ccd, _ := json.Marshal(oAdmin.getCcd(req.Username))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var ccd Ccd
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
	}
	if err := validateUsername(ccd.User); err != nil {
		http.Error(w, `{"error":"invalid username"}`, http.StatusBadRequest)
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
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}
