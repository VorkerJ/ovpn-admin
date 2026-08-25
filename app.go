package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"ovpn-admin/internal/ovpnuser"
	"ovpn-admin/internal/storage"
)

//go:embed templates
var templatesFS embed.FS

//go:embed frontend/static
var staticFS embed.FS

type OvpnAdmin struct {
	// clients is read by handlers and written by setState()/userListHandler.
	// All access MUST go through updateClients / snapshotClients to honor
	// clientsMu; direct access is a race that go test -race will flag.
	clients              []OpenvpnClient
	clientsMu            sync.RWMutex
	activeClients        []clientStatus
	promRegistry         *prometheus.Registry
	mgmtInterfaces       map[string]string
	templates            fs.FS
	modules              []string
	mgmtStatusTimeFormat string
	createUserMutex      *sync.Mutex
	commonRoutes         *commonRoutesStore
	firewall             *firewallController
	serverConfigStore    *serverConfigStore
	serverManager        *serverManager
	store                storage.Store
	mfaStore             *mfaStore
	traffic              *trafficAccountant
	apiTokens            *apiTokenStore
}

// updateClients refreshes the cached clients slice under clientsMu.
// Always prefer this over direct `oAdmin.clients = …` assignment so concurrent
// snapshotClients readers see a consistent slice header.
func (oAdmin *OvpnAdmin) updateClients() {
	list := oAdmin.usersList()
	oAdmin.clientsMu.Lock()
	oAdmin.clients = list
	oAdmin.clientsMu.Unlock()
}

// snapshotClients returns a defensive copy of the cached client list.
// Returning a copy (rather than a borrowed slice under RLock) lets the caller
// iterate without holding the read lock — important because callers like
// rerenderAllCcds do expensive per-item work.
func (oAdmin *OvpnAdmin) snapshotClients() []OpenvpnClient {
	oAdmin.clientsMu.RLock()
	defer oAdmin.clientsMu.RUnlock()
	out := make([]OpenvpnClient, len(oAdmin.clients))
	copy(out, oAdmin.clients)
	return out
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type openvpnClientConfig struct {
	Hosts       []OpenvpnServer
	CA          string
	Cert        string
	Key         string
	TLS         string
	TLSAuthMode string // "tls-auth" | "tls-crypt"; empty -> tls-auth (back-compat)
	PasswdAuth  bool
	// MgmtClientAuth mirrors the server-config flag: when the server runs with
	// `management-client-auth`, OpenVPN requires the client to send
	// username/password, so the template must emit `auth-user-pass` too.
	MgmtClientAuth bool
}

type OpenvpnClient struct {
	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
	PasswordRequired bool   `json:"PasswordRequired"` // has an active VPN password (per-user password auth)
}

type ccdRoute struct {
	Kind           string   `json:"Kind,omitempty"` // "ip" (default) | "domain"
	Address        string   `json:"Address,omitempty"`
	Mask           string   `json:"Mask,omitempty"`
	Domain         string   `json:"Domain,omitempty"`
	Description    string   `json:"Description"`
	ResolvedIPs    []string `json:"ResolvedIPs,omitempty"`
	LastResolveAt  string   `json:"LastResolveAt,omitempty"`
	LastResolveErr string   `json:"LastResolveErr,omitempty"`
}

// Subnet — IPv4 network in dotted-quad form (Address + Mask), with optional
// human-readable description. Used for redirect-gateway exclusions both
// globally (ServerConfig.RedirectGatewayExclusions) and per-user
// (Ccd.RedirectGatewayExclusions). Lower-case JSON tags so the frontend
// can share a single component for both contexts.
type Subnet struct {
	Address     string `json:"address"`
	Mask        string `json:"mask"`
	Description string `json:"description,omitempty"`
}

type Ccd struct {
	User             string           `json:"User"`
	ClientAddress    string           `json:"ClientAddress"`
	CustomRoutes     []ccdRoute       `json:"CustomRoutes"`
	CommonRoutes     []ccdCommonRoute `json:"-"` // not serialized over API, render-only
	MergedPushRoutes []pushRoute      `json:"-"` // computed at render time; unique by (Address, Mask)

	// RedirectGateway — per-user "send all traffic through VPN" toggle.
	// When true, the CCD renders `push "redirect-gateway def1"` plus the
	// union (deduped) of global ServerConfig.RedirectGatewayExclusions and
	// the per-user RedirectGatewayExclusions below, each as a
	// `push "route X Y net_gateway"` directive.
	RedirectGateway bool `json:"RedirectGateway"`

	// RedirectGatewayExclusions — per-user EXTRA subnets that should bypass
	// the VPN even when full-tunnel is on (e.g. a user's specific work VPN
	// subnet on top of the typical 192.168/16 defaults). Globals from
	// ServerConfig always apply; this list adds to them.
	RedirectGatewayExclusions []Subnet `json:"RedirectGatewayExclusions"`

	// MergedExclusions — render-time union of global + per-user exclusions,
	// deduped by (Address, Mask). Not serialized over API.
	MergedExclusions []renderedExclusion `json:"-"`
}

// renderedExclusion is one entry emitted into the CCD as a
// `push "route X Y net_gateway"` line. Source carries the marker
// comment used by parseCcd to round-trip the entry back to its origin
// (global vs per-user) so the operator-side state survives a re-read.
type renderedExclusion struct {
	Address string
	Mask    string
	Source  string // either "__exclusion_global__ desc" or "__exclusion_user__ desc"
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

type clientStatus struct {
	CommonName              string
	RealAddress             string
	BytesReceived           string
	BytesSent               string
	ConnectedSince          string
	VirtualAddress          string
	LastRef                 string
	ConnectedSinceFormatted string
	LastRefFormatted        string
	ConnectedTo             string
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients, _ = oAdmin.mgmtGetActiveClients()
	if oAdmin.traffic != nil {
		oAdmin.traffic.update(oAdmin.activeClients)
		oAdmin.traffic.persist()
	}
	oAdmin.updateClients()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		go oAdmin.setState()
	}
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	// Per-user "has VPN password" — one DB read for the whole list, only when
	// password auth is active (env global or the server-config toggle).
	var pwUsers map[string]bool
	if *authByPassword || (oAdmin.serverConfigStore != nil && oAdmin.serverConfigStore.snapshot().PasswordAuth) {
		pwUsers = ovpnuser.ActivePasswordUsers(*authDatabase)
	}

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.Identity != "server" && !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch line.Flag {
			case "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))

			if (parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) < 0 {
				ovpnClient.AccountStatus = "Expired"
			}
			ovpnClient.Connections = 0
			ovpnClient.PasswordRequired = pwUsers[line.Identity]

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			users = append(users, ovpnClient)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if checkUserExist(username) {
		var hosts []OpenvpnServer

		for _, server := range *openvpnServer {
			parts := strings.SplitN(server, ":", 3)
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
		}

		// If ServerConfig UI has overrides, apply them to the first host
		if oAdmin.serverConfigStore != nil && len(hosts) > 0 {
			sc := oAdmin.serverConfigStore.snapshot()
			if sc.PublicHostname != "" {
				hosts[0].Host = sc.PublicHostname
			}
			if sc.PublicPort != 0 {
				hosts[0].Port = strconv.Itoa(sc.PublicPort)
			}
			if sc.PublicProto != "" {
				hosts[0].Protocol = sc.PublicProto
			}
		}

		if *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		log.Tracef("hosts for %s\n %v", username, hosts)

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		conf.Cert, conf.Key = oAdmin.store.GetClientCert(username)

		conf.PasswdAuth = oAdmin.userRequiresPassword(username)

		if oAdmin.serverConfigStore != nil {
			sc := oAdmin.serverConfigStore.snapshot()
			conf.TLSAuthMode = sc.TLSAuthMode
			conf.MgmtClientAuth = sc.MgmtClientAuth
		}

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		hosts = nil //nolint:ineffassign

		log.Tracef("Rendered config for user %s (%d bytes)", username, tmp.Len())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		data, err := fs.ReadFile(oAdmin.templates, "client.conf.tpl")
		if err != nil {
			log.Errorf("clientConfigTpl not found in embedded templates: %v", err)
		}
		return template.Must(template.New("client-config").Parse(string(data)))
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			// case strings.HasPrefix(str[0], "E"):
			case strings.HasPrefix(str[0], "V"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: str[4][strings.Index(str[4], "=")+1:]})
			case strings.HasPrefix(str[0], "R"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: str[5][strings.Index(str[5], "=")+1:]})
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch line.Flag {
		case "V":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
			// case "E":
		}
	}
	return indexTxt
}

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"script-src 'self'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		// Block legacy Flash/Acrobat cross-domain policy lookups (defense in
		// depth — ovpn-admin never serves a crossdomain.xml, but an
		// upstream proxy or sibling vhost might).
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		// HSTS: only emit when we expect HTTPS. --insecure-cookies signals an
		// HTTP-only dev setup, so omitting the header there avoids pinning a
		// browser to an upstream we don't actually have.
		if !*insecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Build the API prefix from the configured base-url so non-root
		// deployments (e.g. --listen.base-url=/admin/) still get the
		// no-store headers on every JSON response.
		apiPrefix := "/api/"
		if base := strings.TrimRight(*listenBaseUrl, "/"); base != "" {
			apiPrefix = base + "/api/"
		}
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vite emits content-hashed assets under /assets/ (e.g.
		// index-A9TBuVyj.js) — their content can never change for a given URL,
		// so cache them hard. index.html and everything else must NOT be
		// long-cached: it references the current asset hashes, so a stale copy
		// keeps a client on an old frontend after an upgrade (the cause of
		// "I deployed but the UI didn't change"). no-cache forces revalidation.
		if strings.Contains(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		h.ServeHTTP(w, r)
	})
}

type serverSettingsResponse struct {
	Status            string   `json:"status"`
	Modules           []string `json:"modules"`
	ServerInitialized bool     `json:"serverInitialized"`
	AdminMfaEnabled   bool     `json:"adminMfaEnabled"`
	AdminMfaRequired  bool     `json:"adminMfaRequired"`
	// AdminPasswordChangeRequired — admin is on a temporary password and must
	// rotate it before any other action; the UI shows a forced change screen.
	AdminPasswordChangeRequired bool `json:"adminPasswordChangeRequired"`
}

// adminHasMfa returns true if the current admin has MFA enabled.
// Returns true (= allowed) when MFA is server-side disabled (--mfa=false)
// or when --mfa.required=false, so we don't break dev environments where
// MFA is off entirely.
func (oAdmin *OvpnAdmin) adminHasMfa(r *http.Request) bool {
	if isServiceAccount(r) {
		return true // API tokens are a non-interactive credential; MFA N/A
	}
	if oAdmin.mfaStore == nil {
		return true // MFA disabled server-side
	}
	if mfaRequired != nil && !*mfaRequired {
		return true // explicit opt-out
	}
	user := oAdmin.sessionUser(r)
	if user == "" {
		return false
	}
	return oAdmin.mfaStore.isEnabled(user)
}

// serverSettingsHandler GET /api/server/settings.
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	// Если модуль server-config отключён — гейт неприменим, считаем
	// сервер всегда инициализированным (поведение как до фичи).
	initialized := true
	if oAdmin.serverConfigStore != nil {
		initialized = oAdmin.serverConfigStore.snapshot().Initialized
	}

	modules := oAdmin.modules
	if modules == nil {
		modules = []string{}
	}
	// Password auth is toggled at runtime from the server-config UI, so surface
	// the passwdAuth module dynamically (when OVPN_AUTH was set at startup it is
	// already in oAdmin.modules). This makes the per-user password actions appear
	// without restarting.
	if oAdmin.serverConfigStore != nil && oAdmin.serverConfigStore.snapshot().PasswordAuth {
		has := false
		for _, m := range modules {
			if m == "passwdAuth" {
				has = true
				break
			}
		}
		if !has {
			modules = append(append([]string{}, modules...), "passwdAuth")
		}
	}

	// adminMfaRequired is true only when MFA is enabled server-side AND
	// --mfa.required=true. Frontend uses this to decide whether to show
	// the enforcement banner.
	adminMfaRequired := oAdmin.mfaStore != nil && (mfaRequired == nil || *mfaRequired)
	adminMfaEnabled := oAdmin.adminHasMfa(r)

	writeJSON(w, http.StatusOK, serverSettingsResponse{
		Status:                      "ok",
		Modules:                     modules,
		ServerInitialized:           initialized,
		AdminMfaEnabled:             adminMfaEnabled,
		AdminMfaRequired:            adminMfaRequired,
		AdminPasswordChangeRequired: adminPasswordChangeRequired(),
	})
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
		return time.Now()
	}

	certPem, _ := pem.Decode(caCert)
	if certPem == nil {
		log.Errorf("error decode certificate ca.crt: no PEM block found in %s", caCertPath)
		return time.Now()
	}
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(fRead(kubeNamespaceFilePath)).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status from kube api %v", service.Status)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		lbIngress := service.Status.LoadBalancer.Ingress
		if len(lbIngress) > 0 {
			if lbIngress[0].Hostname != "" {
				lbHost = lbIngress[0].Hostname
			}

			if lbIngress[0].IP != "" {
				lbHost = lbIngress[0].IP
			}
		}

		hosts = append(hosts, OpenvpnServer{lbHost, strconv.Itoa(int(service.Spec.Ports[0].Port)), strings.ToLower(string(service.Spec.Ports[0].Protocol))})
	}

	if len(hosts) == 0 {
		return []OpenvpnServer{{Host: "kubernetes services not found"}}, err
	}

	return hosts, nil
}
