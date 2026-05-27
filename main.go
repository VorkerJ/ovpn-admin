package main

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"gopkg.in/alecthomas/kingpin.v2"

	"ovpn-admin/internal/storage"
)

const (
	usernameRegexp         = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength      = 6
	certsArchiveFileName   = "certs.tar.gz"
	ccdArchiveFileName     = "ccd.tar.gz"
	indexTxtDateLayout     = "060102150405Z"
	stringDateFormat       = "2006-01-02 15:04:05"
	downloadCertsApiUrl    = "api/data/certs/download"
	downloadCcdApiUrl      = "api/data/ccd/download"
	labelKeyIndexTxt       = "index.txt"
	labelKeyType           = "type"
	labelKeyName           = "name"
	labelKeyManagedBy      = "app.kubernetes.io/managed-by"
	labelValueClientAuth   = "clientAuth"
	labelValueManagedByApp = "ovpn-admin"
	prefixStaticRoute      = "ifconfig-push"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	listenBaseUrl            = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("OVPN_INDEX_PATH").String()
	easyrsaBinPath           = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	authDataBaseInit         = kingpin.Flag("auth.db-init", "enable database initialization if db user not exists or size is 0").Default("false").Envar("OVPN_AUTH_DB_INIT").Bool()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	clientCertExpirationDays = kingpin.Flag("client-cert.expiration-days", "Expiration period of OpenVPN client certificates in days, the period will shrink automatically to the CA expiration period").Default("3650").Envar("CLIENT_CERT_EXPIRATION_DAYS").String()
	adminHtpasswdFile        = kingpin.Flag("admin.htpasswd-file", "path to htpasswd file with admin UI credentials; if empty, a random password is generated").Default("").Envar("ADMIN_HTPASSWD_FILE").String()
	commonRoutesEnabled      = kingpin.Flag("common-routes", "enable common routes feature").Default("true").Envar("OVPN_COMMON_ROUTES").Bool()

	serverConfigEnabled = kingpin.Flag("server-config",
		"enable editable server config UI feature").
		Default("true").Envar("OVPN_SERVER_CONFIG").Bool()

	serverConfigPath = kingpin.Flag("server-config.conf-path",
		"path where ovpn-admin writes the rendered server.conf").
		Default("/etc/openvpn/server.conf").Envar("OVPN_SERVER_CONFIG_PATH").String()

	firewallEnabled = kingpin.Flag("firewall",
		"enable per-client iptables enforcement").
		Default("false").Envar("OVPN_FIREWALL").Bool()

	firewallChainName = kingpin.Flag("firewall.chain-name",
		"iptables chain name for ovpn-admin rules").
		Default("OVPN_FW").Envar("OVPN_FIREWALL_CHAIN").String()

	firewallIptablesBin = kingpin.Flag("firewall.iptables-bin",
		"path to iptables binary").
		Default("iptables").Envar("OVPN_FIREWALL_IPTABLES_BIN").String()

	firewallStartupTimeout = kingpin.Flag("firewall.startup-timeout",
		"max time to wait for first mgmt connection before failing startup").
		Default("30s").Envar("OVPN_FIREWALL_STARTUP_TIMEOUT").Duration()

	firewallReconcileInterval = kingpin.Flag("firewall.reconcile-interval",
		"self-heal reconcile period").
		Default("5m").Envar("OVPN_FIREWALL_RECONCILE_INTERVAL").Duration()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	version = "2.0.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if *masterSyncToken == "VerySecureToken" {
		log.Warn("SECURITY: --master.sync-token uses the insecure default. Set OVPN_MASTER_TOKEN to a strong random value!")
	}

	initAuth()

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}

	var store storage.Store
	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Fatal(err)
		}
		store = &kubernetesStore{pki: &app}
	} else {
		store = &filesystemStore{
			easyrsaDirPath: *easyrsaDirPath,
			easyrsaBinPath: *easyrsaBinPath,
			ccdDir:         *ccdDir,
			indexTxtPath:   *indexTxtPath,
		}
	}

	if *authDataBaseInit {
		ovpnUserInitDb()
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)
	ovpnAdmin.commonRoutes = &commonRoutesStore{cfg: CommonRoutesConfig{Routes: []CommonRouteEntry{}}}
	ovpnAdmin.store = store

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	ovpnAdmin.mgmtSetTimeFormat()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if _, isK8s := store.(*kubernetesStore); !isK8s {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if *commonRoutesEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "common-routes")

		// Use ccdDir as the config location for filesystem backend (same dir as CCD files)
		ovpnAdmin.commonRoutesPath = *ccdDir + "/_common_routes.json"

		var initial CommonRoutesConfig
		data, err := store.LoadCommonRoutes()
		if err != nil {
			log.Warnf("loading common routes: %v (starting with empty)", err)
		}
		if data != nil {
			if c, derr := deserializeCommonRoutes(data); derr != nil {
				log.Warnf("deserializing common routes: %v (starting with empty)", derr)
			} else {
				initial = c
			}
		}
		ovpnAdmin.commonRoutes.replace(initial)

		go ovpnAdmin.runCommonRoutesScheduler()
	}

	if *serverConfigEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "server-config")

		storagePath := *ccdDir + "/_server_config.json"

		ovpnAdmin.serverConfigStore = newServerConfigStore()
		var initial ServerConfig
		data, err := store.LoadServerConfig()
		if err != nil {
			log.Warnf("load server config: %v (using defaults)", err)
			initial = defaultServerConfig()
		} else if data == nil {
			initial = defaultServerConfig()
		} else {
			c, derr := deserializeServerConfig(data)
			if derr != nil {
				log.Warnf("deserialize server config: %v (using defaults)", derr)
				initial = defaultServerConfig()
			} else {
				initial = c
			}
		}
		ovpnAdmin.serverConfigStore.replace(initial)

		dcoAvailable := detectDCOSupport()
		log.Infof("server-config: DCO support detected: %v", dcoAvailable)
		if dcoAvailable {
			ovpnServerConfigDCOAvailable.Set(1)
		} else {
			ovpnServerConfigDCOAvailable.Set(0)
		}

		mgmtAddr, ok := ovpnAdmin.mgmtInterfaces["main"]
		if !ok {
			mgmtAddr = "127.0.0.1:8989"
		}

		ovpnAdmin.serverManager = &serverManager{
			store:          ovpnAdmin.serverConfigStore,
			persistBackend: store,
			storagePath:    storagePath,
			mgmtAddr:       mgmtAddr,
			confPath:       *serverConfigPath,
			dcoAvailable:   dcoAvailable,
			ccdEnabled:     *ccdEnabled,
		}

		// Render initial server.conf at startup (openvpn-container waits for this file)
		rendered, err := renderServerConfig(initial, dcoAvailable, *ccdEnabled)
		if err != nil {
			log.Fatalf("server-config: initial render failed: %v", err)
		}
		if err := writeFileAtomic(*serverConfigPath, []byte(rendered)); err != nil {
			log.Warnf("server-config: cannot write initial %s: %v (openvpn-container won't start)", *serverConfigPath, err)
		} else {
			log.Infof("server-config: rendered initial config to %s", *serverConfigPath)
		}
	}

	if *firewallEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "firewall")

		// fail-fast: проверим что iptables бинарь доступен
		if _, err := exec.LookPath(*firewallIptablesBin); err != nil {
			log.Fatalf("firewall enabled but iptables binary %q not found: %v", *firewallIptablesBin, err)
		}

		_, vpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Fatalf("firewall: cannot parse --ovpn.network=%s: %v", *openvpnNetwork, err)
		}

		mgmtAddr, ok := ovpnAdmin.mgmtInterfaces["main"]
		if !ok {
			log.Fatalf("firewall: no mgmt interface 'main' configured; got %v", ovpnAdmin.mgmtInterfaces)
		}

		ovpnAdmin.firewall = newFirewallController(
			ovpnAdmin,
			*firewallChainName,
			*firewallIptablesBin,
			vpnNet,
			realIptCmd(*firewallIptablesBin),
		)
		ovpnAdmin.firewall.mgmtSnapshot = ovpnAdmin.mgmtGetActiveClients

		ctx := context.Background()
		if err := ovpnAdmin.firewall.Start(ctx, mgmtAddr, *firewallReconcileInterval); err != nil {
			log.Fatalf("firewall: Start failed: %v", err)
		}
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	tplSub, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		log.Fatalf("cannot create sub-FS for templates: %v", err)
	}
	ovpnAdmin.templates = tplSub

	staticSub, err := fs.Sub(staticFS, "frontend/static")
	if err != nil {
		log.Fatalf("cannot create sub-FS for static: %v", err)
	}
	static := CacheControlWrapper(http.FileServer(http.FS(staticSub)))

	http.Handle(*listenBaseUrl, http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/"), static))

	// Public auth endpoints
	http.HandleFunc(*listenBaseUrl+"api/login", ovpnAdmin.loginHandler)
	http.HandleFunc(*listenBaseUrl+"api/logout", ovpnAdmin.requireAuth(ovpnAdmin.logoutHandler))
	http.HandleFunc(*listenBaseUrl+"api/auth/check", ovpnAdmin.requireAuth(ovpnAdmin.authCheckHandler))

	// Protected API endpoints
	http.HandleFunc(*listenBaseUrl+"api/server/settings", ovpnAdmin.requireAuth(ovpnAdmin.serverSettingsHandler))
	http.HandleFunc(*listenBaseUrl+"api/users/list", ovpnAdmin.requireAuth(ovpnAdmin.userListHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/create", ovpnAdmin.requireAuth(ovpnAdmin.userCreateHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/change-password", ovpnAdmin.requireAuth(ovpnAdmin.userChangePasswordHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/rotate", ovpnAdmin.requireAuth(ovpnAdmin.userRotateHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/delete", ovpnAdmin.requireAuth(ovpnAdmin.userDeleteHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/revoke", ovpnAdmin.requireAuth(ovpnAdmin.userRevokeHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/unrevoke", ovpnAdmin.requireAuth(ovpnAdmin.userUnrevokeHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/config/show", ovpnAdmin.requireAuth(ovpnAdmin.userShowConfigHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/disconnect", ovpnAdmin.requireAuth(ovpnAdmin.userDisconnectHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/statistic", ovpnAdmin.requireAuth(ovpnAdmin.userStatisticHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/ccd", ovpnAdmin.requireAuth(ovpnAdmin.userShowCcdHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/ccd/apply", ovpnAdmin.requireAuth(ovpnAdmin.userApplyCcdHandler))
	http.HandleFunc(*listenBaseUrl+"api/common-routes", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesHandler))
	http.HandleFunc(*listenBaseUrl+"api/common-routes/refresh", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesRefreshHandler))
	http.HandleFunc(*listenBaseUrl+"api/common-routes/", ovpnAdmin.requireAuth(ovpnAdmin.commonRoutesItemHandler))
	http.HandleFunc(*listenBaseUrl+"api/server-config", ovpnAdmin.requireAuth(ovpnAdmin.serverConfigHandler))
	http.HandleFunc(*listenBaseUrl+"api/server-config/test", ovpnAdmin.requireAuth(ovpnAdmin.serverConfigTestHandler))
	http.HandleFunc(*listenBaseUrl+"api/server-config/defaults", ovpnAdmin.requireAuth(ovpnAdmin.serverConfigDefaultsHandler))

	http.HandleFunc(*listenBaseUrl+"api/sync/last/try", ovpnAdmin.requireAuth(ovpnAdmin.lastSyncTimeHandler))
	http.HandleFunc(*listenBaseUrl+"api/sync/last/successful", ovpnAdmin.requireAuth(ovpnAdmin.lastSuccessfulSyncTimeHandler))
	http.HandleFunc(*listenBaseUrl+downloadCertsApiUrl, ovpnAdmin.requireAuth(ovpnAdmin.downloadCertsHandler))
	http.HandleFunc(*listenBaseUrl+downloadCcdApiUrl, ovpnAdmin.requireAuth(ovpnAdmin.downloadCcdHandler))

	http.HandleFunc(*metricsPath, ovpnAdmin.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}))
	http.HandleFunc(*listenBaseUrl+"ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s%s", *listenHost, *listenPort, *listenBaseUrl)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, securityMiddleware(http.DefaultServeMux)))
}
