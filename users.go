package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// ovpnUserInitDb initializes the openvpn-user password database when missing
// or zero-byte (Docker bind mounts often pre-create the path as empty).
// Triggered by --auth.db-init=true; safe to call at every startup.
func ovpnUserInitDb() {
	fi, err := os.Stat(*authDatabase)
	// Init only when the DB file is missing or zero-byte. Any other stat error
	// (permission denied, transient IO) — skip init; we can't safely overwrite.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil && fi.Size() > 0 {
		return
	}
	// Execute via runOpenvpnUser (argv-based exec.Command) rather than
	// runBash(fmt.Sprintf(...)). Shell interpolation of *authDatabase was a
	// command-injection vector if the operator pointed --auth-database at a
	// path containing shell metacharacters.
	// Init failures are non-fatal (subsequent password ops will surface a real
	// error); just log at debug.
	o, _ := runOpenvpnUser("--db.path", *authDatabase, "db-init")
	log.Debug(o)
	o, _ = runOpenvpnUser("--db.path", *authDatabase, "db-migrate")
	log.Debug(o)
}

// mustJSONMsg encodes a "msg" envelope safely. Inline string concatenation in
// the old code (`{"msg":"User \"%s\" not found"}`) produced invalid JSON when
// username contained quotes or interpolation broke the quoting. encoding/json
// handles escaping for us.
func mustJSONMsg(msg string) string {
	data, err := json.Marshal(map[string]string{"msg": msg})
	if err != nil {
		// Fallback: defensively produce a static valid JSON string. Marshal of
		// map[string]string{} cannot fail in practice but the fallback keeps
		// the API contract intact.
		return `{"msg":"internal error"}`
	}
	return string(data)
}

// runOpenvpnUser executes the openvpn-user CLI and returns its trimmed output
// together with the process error. Callers on the password-auth path MUST check
// the error and propagate it — otherwise a failed openvpn-user step (e.g. a
// locked/permission-denied users.db) is silently swallowed and the API reports
// success while the user's password state is wrong.
//
// It is a package var so tests can substitute a fake runner without spawning
// the real binary.
//
// NOTE: the password is still passed as an argv --password flag (visible in
// `ps aux` while the subprocess runs). Migrating it to stdin/env requires
// upstream openvpn-user support we cannot verify here — a known limitation.
var runOpenvpnUser = func(args ...string) (string, error) {
	cmd := exec.Command("openvpn-user", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Redact --password values from logged args.
		safeArgs := make([]string, len(args))
		copy(safeArgs, args)
		for i, a := range safeArgs {
			if a == "--password" && i+1 < len(safeArgs) {
				safeArgs[i+1] = "[REDACTED]"
			}
		}
		head := safeArgs
		if len(head) > 2 {
			head = safeArgs[:2]
		}
		log.Warnf("openvpn-user %v: %v: %s", head, err, string(out))
	}
	return strings.TrimSpace(string(out)), err
}

// openvpnUserSucceeds runs openvpn-user and reports whether it exited 0. Used
// for predicate subcommands like `has-password`, whose answer is the exit code.
func openvpnUserSucceeds(args ...string) bool {
	return exec.Command("openvpn-user", args...).Run() == nil
}

// userHasVpnPassword reports whether the user has an active password entry in
// users.db (i.e. is "password-required" for VPN connect).
func userHasVpnPassword(username string) bool {
	if *authDatabase == "" {
		return false
	}
	return openvpnUserSucceeds("has-password", "--db.path", *authDatabase, "--user", username)
}

// userRequiresPassword decides whether user X must present a VPN password on
// connect. Legacy OVPN_AUTH forces it for everyone (global mode); otherwise it
// is per-user: the server-wide PasswordAuth toggle is on AND the user has an
// active password in users.db. Drives whether the user's .ovpn gets
// `auth-user-pass`.
func (oAdmin *OvpnAdmin) userRequiresPassword(username string) bool {
	if *authByPassword {
		return true
	}
	if oAdmin.serverConfigStore == nil || !oAdmin.serverConfigStore.snapshot().PasswordAuth {
		return false
	}
	return userHasVpnPassword(username)
}

// passwordAuthActive reports whether VPN password auth is available at all —
// legacy global env OR the runtime server-config toggle. Gates the per-user
// password set/remove endpoints and the passwdAuth UI module.
func (oAdmin *OvpnAdmin) passwordAuthActive() bool {
	if *authByPassword {
		return true
	}
	return oAdmin.serverConfigStore != nil && oAdmin.serverConfigStore.snapshot().PasswordAuth
}

type usernameRequest struct {
	Username string `json:"username"`
}

type usernamePasswordRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HTTP method check is enforced by requireMethod middleware at route
// registration time; do not re-check it inside handlers.

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	// Storage refresh failures should not block the response — the cached
	// client list is still useful for read-only display and panicking would
	// log out the admin for no actionable reason.
	if err := oAdmin.store.UpdateIndexTxtOnDisk(); err != nil {
		log.Errorf("userListHandler: UpdateIndexTxtOnDisk: %v", err)
	}
	oAdmin.updateClients()
	clients := oAdmin.snapshotClients()
	if clients == nil {
		clients = []OpenvpnClient{}
	}

	w.Header().Set("Content-Type", "application/json")
	usersList, err := json.Marshal(clients)
	if err != nil {
		log.Errorf("userListHandler: marshal: %v", err)
		fmt.Fprint(w, "[]")
		return
	}
	fmt.Fprint(w, string(usersList))
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(req.Username))
	fmt.Fprint(w, string(userStatistic))
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	// Гейт: если модуль server-config включён и admin ещё не сохранял
	// настройки через UI — блокируем создание (defaults на диске нужны
	// только чтобы openvpn-сервер стартовал, это не означает что admin
	// согласен с этими параметрами).
	if oAdmin.serverConfigStore != nil && !oAdmin.serverConfigStore.snapshot().Initialized {
		writeJSONError(w, http.StatusPreconditionFailed, "server not initialized — configure server in UI first")
		return
	}
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Validate at the handler edge BEFORE any disk lookup, so a path-
	// traversal username never reaches checkUserExist or store calls.
	if err := validateUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	userCreated, userCreateStatus := oAdmin.userCreate(req.Username, req.Password)

	if userCreated {
		oAdmin.updateClients()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	// Ротация выпускает новый сертификат, поэтому блокируется тем же
	// гейтом что и создание пользователя.
	if oAdmin.serverConfigStore != nil && !oAdmin.serverConfigStore.snapshot().Initialized {
		writeJSONError(w, http.StatusPreconditionFailed, "server not initialized — configure server in UI first")
		return
	}
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	err, msg := oAdmin.userRotate(req.Username, req.Password)
	if err != nil {
		log.Errorf("userRotate: %v", err)
		writeJSONError(w, http.StatusBadRequest, "failed to rotate user")
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	err, msg := oAdmin.userDelete(req.Username)
	if err != nil {
		log.Errorf("userDelete: %v", err)
		writeJSONError(w, http.StatusBadRequest, "failed to delete user")
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	err, msg := oAdmin.userRevoke(req.Username)
	if err != nil {
		log.Errorf("userRevoke: %v", err)
		writeJSONError(w, http.StatusBadRequest, "failed to revoke user")
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	err, msg := oAdmin.userUnrevoke(req.Username)
	if err != nil {
		log.Errorf("userUnrevoke: %v", err)
		writeJSONError(w, http.StatusBadRequest, "failed to unrevoke user")
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !oAdmin.passwordAuthActive() {
		writeJSONError(w, http.StatusNotImplemented, "password auth disabled")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	err, msg := oAdmin.userChangePassword(req.Username, req.Password)
	if err != nil {
		log.Errorf("userChangePassword: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": msg,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": msg,
	})
}

// userRemovePasswordHandler POST /api/user/remove-password — drops a user's VPN
// password so they become cert-only again. Hard-deletes the users.db row (so a
// later set-password is clean), then the next .ovpn download omits auth-user-pass.
func (oAdmin *OvpnAdmin) userRemovePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !oAdmin.passwordAuthActive() {
		writeJSONError(w, http.StatusNotImplemented, "password auth disabled")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	o, err := runOpenvpnUser("delete", "--db.path", *authDatabase, "--user", req.Username, "--force")
	log.Debugf("userRemovePassword %s: %s", req.Username, o)
	if err != nil {
		// Don't report success when the openvpn-user delete failed — the user
		// would keep their password entry while the UI showed it removed.
		log.Errorf("userRemovePassword %s: %v", req.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to remove password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Пароль удалён — пользователь снова только по сертификату",
	})
}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Невалидное имя пользователя")
		return
	}
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(req.Username))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := validateExistingUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	if !checkUserExist(req.Username) {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	// Audit N05 (sibling of killUserSessions): a "disconnect now" action must
	// decide off the LIVE mgmt console, not the ~28s cache. Off a stale-empty
	// cache this endpoint would report "disconnected: 0 / ok" while the user is
	// actually still tunnelling. If the live poll can't be completed, say so
	// instead of falsely confirming there was nothing to disconnect.
	active, ok := oAdmin.mgmtGetActiveClients()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":    false,
			"error": "cannot confirm live sessions: management interface unreachable or returned an incomplete status",
		})
		return
	}
	connected, connections := isUserConnected(req.Username, active)
	if !connected {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "disconnected": 0})
		return
	}

	// Count only acknowledged kills (audit F13): report the true number of
	// sessions actually terminated, not the number we attempted.
	killed := 0
	var failures []string
	for _, conn := range connections {
		if err := oAdmin.mgmtKillUserConnection(req.Username, conn); err != nil {
			failures = append(failures, err.Error())
		} else {
			killed++
		}
	}
	resp := map[string]interface{}{"ok": len(failures) == 0, "disconnected": killed}
	if len(failures) > 0 {
		resp["error"] = strings.Join(failures, "; ")
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// internalCcdBlobNames are the reserved basenames of the server's own config
// blobs stored alongside CCD files. A client CN equal to one of these must never
// reach SaveCcd/DeleteClient (audit F06/N19), or a client endpoint could
// overwrite or delete the server config / common-routes state.
var internalCcdBlobNames = map[string]bool{
	"_server_config.json": true,
	"_common_routes.json": true,
}

// validateUsername validates a CN for CREATING a new client (strictest form):
// it additionally rejects ANY leading underscore, which is reserved for the
// server's internal blobs. This is the choke point BuildClient/SaveCcd funnel
// through.
func validateUsername(username string) error {
	return validateUsernameCommon(username, false)
}

// validateExistingUsername validates a CN for operations on an ALREADY EXISTING
// client (revoke/unrevoke/delete/rotate/config-export/disconnect). Audit N19:
// older versions allowed CNs starting with "_", so such clients may exist in the
// PKI and MUST stay manageable (an operator has to be able to revoke/delete
// them). Only the exact internal blob names (_server_config.json,
// _common_routes.json) remain reserved, so a client endpoint can never touch the
// server-config/common-routes files.
func validateExistingUsername(username string) error {
	return validateUsernameCommon(username, true)
}

func validateUsernameCommon(username string, allowExistingUnderscore bool) error {
	if username == "" || username == "." || username == ".." {
		return errors.New("Имя пользователя не может быть пустым или состоять только из точек")
	}
	if strings.Contains(username, "/") || strings.Contains(username, "\\") {
		return errors.New("Имя пользователя не может содержать слэши")
	}
	// Audit F07: reject reserved PKI identities. "server"/"ca" are the VPN
	// server and CA certificates, NOT client accounts — without this guard a
	// service token or admin could revoke/delete/rotate the server identity
	// (stopping the VPN) or export the server private key through the
	// client-config endpoint, and a client created with CN "server" would
	// collide with the server cert. "REVOKED…" is the archival rename marker for
	// rotated/deleted certs, never a real account. This is the single choke point
	// every user endpoint and store method (BuildClient/SaveCcd/GetClientCert)
	// funnels through.
	switch strings.ToLower(username) {
	case "server", "ca", "default":
		return errors.New("Имя зарезервировано за сертификатом сервера/CA/DEFAULT и недоступно для клиентских операций")
	}
	if strings.HasPrefix(username, "REVOKED") {
		return errors.New("Имя зарезервировано (архивный маркер отозванных сертификатов)")
	}
	// Audit F06: internal config blobs are stored in the CCD directory with a
	// leading underscore (_server_config.json, _common_routes.json). A CN like
	// "_server_config.json" would otherwise pass the regex and let ccd/apply
	// overwrite the server config through SaveCcd. These exact names are ALWAYS
	// reserved, even for management of existing clients.
	if internalCcdBlobNames[username] {
		return errors.New("Имя зарезервировано за служебным файлом сервера и недоступно для клиентских операций")
	}
	// A leading underscore is reserved for internal blobs on CREATE. For
	// management of an already-existing client we allow it (audit N19), because
	// the exact reserved blob names are rejected above.
	if strings.HasPrefix(username, "_") && !allowExistingUnderscore {
		return errors.New("Имя не может начинаться с подчёркивания (зарезервировано за служебными файлами)")
	}
	// Reject leading dashes and `--` sequences. easyrsa does not support a
	// `--` end-of-options marker, so a username like "--whatever" would be
	// parsed as a flag by the easyrsa CLI. Belt-and-suspenders alongside the
	// regex — the regex already requires the first char to be alnum/_/@.
	if strings.HasPrefix(username, "-") || strings.Contains(username, "--") {
		return errors.New("Имя пользователя не может начинаться с дефиса или содержать `--`")
	}
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) {
		return nil
	} else {
		return errors.New("Имя пользователя должно начинаться с буквы/цифры/_/@, длиной до 63 символов, может содержать буквы, цифры и символы: _ . - @")
	}
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < passwordMinLength {
		return fmt.Errorf("Password too short, password length must be greater or equal %d", passwordMinLength)
	} else {
		return nil
	}
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string) {
	// Validate FIRST. Both callers should have already done this at the
	// handler edge, but doing it here too prevents any path-traversal CN
	// from reaching checkUserExist / store.BuildClient.
	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error()
	}

	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if checkUserExist(username) {
		ucErr = fmt.Sprintf("Пользователь \"%s\" уже существует\n", username)
		log.Debugf("userCreate: checkUserExist():  %s", ucErr)
		return false, ucErr
	}

	// Audit F03: honour BOTH the legacy global env (*authByPassword — password
	// required for everyone) and the runtime per-user PasswordAuth toggle
	// (password optional; provision one only when the operator supplied it).
	if *authByPassword || (oAdmin.passwordAuthActive() && password != "") {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: password validation: %s", err.Error())
			return false, err.Error()
		}
	}

	if err := oAdmin.store.BuildClient(username); err != nil {
		log.Errorf("userCreate: BuildClient failed for %s: %v", username, err)
		return false, fmt.Sprintf("Не удалось создать сертификат: %v", err)
	}

	if oAdmin.passwordAuthActive() && password != "" {
		o, err := runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", password)
		log.Debug(o)
		if err != nil {
			// The cert is built but the password entry failed. Leaving the cert
			// would be an orphan VALID credential (can connect cert-only), so
			// roll it back — the operation fails cleanly with no half-created user.
			log.Errorf("userCreate: create password for %s failed, rolling back cert: %v", username, err)
			if delErr := oAdmin.store.DeleteClient(username); delErr != nil {
				log.Errorf("userCreate: rollback DeleteClient(%s) after password failure: %v", username, delErr)
			}
			return false, fmt.Sprintf("Не удалось создать пароль пользователя: %v", err)
		}
	}

	// Seed a clean CCD with the current Common Routes so the very first
	// connect already carries the global push directives. Without this,
	// a freshly-created user has no /etc/openvpn/ccd/<CN> file at all
	// and receives ONLY server-level pushes — Common Routes silently
	// skip them until the next rerenderAllCcds (which only fires on
	// later admin actions). Also wipes any orphan CCD from a previous
	// tenant that shared the same CN — preventing the new user from
	// inheriting the previous owner's per-user routes / fixed IP.
	freshCcd := Ccd{User: username, ClientAddress: "dynamic", CustomRoutes: []ccdRoute{}}
	var commonExpanded []ccdCommonRoute
	if oAdmin.commonRoutes != nil {
		commonExpanded = expandCommonRoutes(oAdmin.commonRoutes.snapshot())
	}
	if ok, msg := oAdmin.modifyCcd(freshCcd, commonExpanded); !ok {
		log.Warnf("userCreate: seed CCD for %s failed: %s", username, msg)
	}

	log.Infof("Certificate for user %s issued", username)
	oAdmin.updateClients()

	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {
	// The PKI cert must exist; this is a real membership check, not a DB probe.
	if !checkUserExist(username) {
		return fmt.Errorf("user %q not found", username), mustJSONMsg(fmt.Sprintf("User %s not found", username))
	}

	if err := validatePassword(password); err != nil {
		log.Warningf("userChangePassword: %s", err.Error())
		return err, err.Error()
	}

	// Audit F04: do NOT parse `check` stdout to decide create-vs-update — the
	// built-in openvpn-user `check` prints nothing, so the old code always tried
	// to `create` an existing user and failed. `change-password` now upserts the
	// row (create if cert-only, update otherwise), so one call handles both cases
	// and any DB/CLI error is a genuine failure — never misread as "no user".
	o, err := runOpenvpnUser("change-password", "--db.path", *authDatabase, "--user", username, "--password", password)
	log.Debug(o)
	if err != nil {
		log.Errorf("userChangePassword: openvpn-user change-password %s: %v", username, err)
		return err, mustJSONMsg("failed to change password")
	}

	log.Infof("Password for user %s was changed", username)
	return nil, "Password changed"
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.snapshotActiveClients() {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

func (oAdmin *OvpnAdmin) userRevoke(username string) (error, string) {
	log.Infof("Revoke certificate for user %s", username)
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		if err := oAdmin.store.RevokeClient(username); err != nil {
			// Don't report success on failure (e.g. denied K8s secret update) —
			// the cert would still be valid and the user could keep connecting.
			log.Errorf("userRevoke: RevokeClient(%s): %v", username, err)
			return err, fmt.Sprintf("failed to revoke user %q: %v", username, err)
		}

		if oAdmin.passwordAuthActive() {
			o, _ := runOpenvpnUser("revoke", "--db.path", *authDatabase, "--user", username)
			log.Debug(o)
		}

		crlFix()
		// Terminate any live tunnel. The cert is already revoked in the CRL, so
		// this is about cutting the ESTABLISHED session immediately; report
		// honestly whether the kill was acknowledged (audit F13) rather than
		// logging an unverified "killed".
		killErr := oAdmin.killUserSessions(username)

		oAdmin.setState()
		if killErr != nil {
			log.Warnf("userRevoke: %s revoked, but live session termination not confirmed: %v", username, killErr)
			return nil, fmt.Sprintf("user %q revoked (CRL updated); live session termination NOT confirmed — verify the user is disconnected: %v", username, killErr)
		}
		return nil, fmt.Sprintf("user \"%s\" revoked", username)
	}
	log.Infof("user \"%s\" not found", username)
	return fmt.Errorf("user %q not found", username), fmt.Sprintf("User %s not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	if checkUserExist(username) {
		if err := oAdmin.store.UnrevokeClient(username); err != nil {
			// Don't report success on a failed storage unrevoke — the cert would
			// stay revoked while the UI says otherwise.
			log.Errorf("userUnrevoke: UnrevokeClient(%s): %v", username, err)
			return err, mustJSONMsg(fmt.Sprintf("Failed to unrevoke user %s: %v", username, err))
		}

		if oAdmin.passwordAuthActive() {
			o, _ := runOpenvpnUser("restore", "--db.path", *authDatabase, "--user", username)
			log.Debug(o)
		}

		crlFix()
		oAdmin.updateClients()
		return nil, mustJSONMsg(fmt.Sprintf("User %s successfully unrevoked", username))
	}
	return fmt.Errorf("user %q not found", username), mustJSONMsg(fmt.Sprintf("User %s not found", username))
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (error, string) {
	if checkUserExist(username) {
		// Validate the new password BEFORE any mutation, so a bad password can't
		// leave the user with its old password already deleted / cert rotated.
		// Validate a supplied new password (required in global mode, optional in
		// per-user mode); always clear any existing password row so the rotated
		// account starts from a clean slate (audit F03).
		if *authByPassword || (oAdmin.passwordAuthActive() && newPassword != "") {
			if err := validatePassword(newPassword); err != nil {
				return fmt.Errorf("rotate: invalid new password: %w", err), err.Error()
			}
		}

		// Audit N01: rotate the CERTIFICATE first, THEN touch the password row.
		// The old order dropped the password before RotateClient, so a PKI failure
		// left the user with the old cert still valid but no password — a silent
		// downgrade from cert+password to cert-only. Rotating first means a PKI
		// failure aborts with BOTH old credentials intact (the rotate simply didn't
		// happen); and if the password step below fails AFTER a successful rotate,
		// password auth is left blocked (fail-closed), never downgraded.
		if err := oAdmin.store.RotateClient(username, newPassword); err != nil {
			log.Error(err)
			return fmt.Errorf("error rotating user: %w", err), err.Error()
		}

		if oAdmin.passwordAuthActive() {
			o, _ := runOpenvpnUser("delete", "--force", "--db.path", *authDatabase, "--user", username)
			log.Debug(o)
		}

		if oAdmin.passwordAuthActive() && newPassword != "" {
			o, err := runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", newPassword)
			log.Debug(o)
			if err != nil {
				// Cert rotated but the new password row failed — surface it
				// instead of a misleading success (the user can't password-auth).
				log.Errorf("userRotate: create password for %s: %v", username, err)
				return fmt.Errorf("rotate: create password: %w", err), mustJSONMsg(fmt.Sprintf("Cert rotated but password update failed: %v", err))
			}
		}

		crlFix()
		oAdmin.updateClients()
		// Audit F13: rotation issues a NEW cert with the SAME CN, so any tunnel
		// still up on the OLD key must be cut — otherwise the rotated-out
		// credential keeps working until the client happens to reconnect.
		killErr := oAdmin.killUserSessions(username)
		if killErr != nil {
			log.Warnf("userRotate: %s rotated, but live session termination not confirmed: %v", username, killErr)
			return nil, mustJSONMsg(fmt.Sprintf("User %s rotated; live session termination NOT confirmed — verify the user reconnects with the new cert: %v", username, killErr))
		}
		return nil, mustJSONMsg(fmt.Sprintf("User %s successfully rotated", username))
	}
	return fmt.Errorf("user %q not found", username), mustJSONMsg(fmt.Sprintf("User %s not found", username))
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	if checkUserExist(username) {
		// Kick BEFORE we delete the on-disk state so the kill command still
		// has a CN to match in OpenVPN's connected-clients table. Without
		// this the deleted user keeps tunnelling traffic until they happen
		// to reconnect — CRL only takes effect at the next TLS handshake,
		// not on already-established sessions. A kill that isn't acknowledged
		// (audit F13) is logged; deletion still proceeds (the cert is revoked
		// below), but the operator is told the live session wasn't confirmed cut.
		if killErr := oAdmin.killUserSessions(username); killErr != nil {
			log.Warnf("userDelete: %s live session termination not confirmed: %v", username, killErr)
		}

		// Audit N01: revoke/delete the CERTIFICATE first. The old order deleted the
		// password row before DeleteClient, so a PKI failure left the cert still
		// valid but the password gone — a silent downgrade to cert-only. Deleting
		// the cert first means a PKI failure aborts with BOTH credentials intact
		// (no change); and once the cert is revoked, the user cannot connect at all,
		// so a subsequent password-DB delete failure is safe (fail-closed).
		if err := oAdmin.store.DeleteClient(username); err != nil {
			// Do NOT report success on failure — the client was still there and
			// tunnelling. Surface the error so the UI shows it (this used to be
			// swallowed, so a denied K8s secret update looked like a success
			// while the user stayed in the list).
			log.Errorf("userDelete: DeleteClient(%s): %v", username, err)
			return err, mustJSONMsg(fmt.Sprintf("Failed to delete user %s: %v", username, err))
		}

		if oAdmin.passwordAuthActive() {
			// The cert is already revoked above, so the user cannot connect
			// regardless; still, propagate a failed password-DB delete so the
			// operator can clean up the orphaned row instead of seeing a false 200.
			if o, err := runOpenvpnUser("delete", "--force", "--db.path", *authDatabase, "--user", username); err != nil {
				log.Errorf("userDelete: openvpn-user delete %s: %v", username, err)
				return err, mustJSONMsg(fmt.Sprintf("User %s cert deleted but password-entry removal failed: %v", username, err))
			} else {
				log.Debug(o)
			}
		}

		crlFix()
		oAdmin.updateClients()
		return nil, mustJSONMsg(fmt.Sprintf("User %s successfully deleted", username))
	}
	return fmt.Errorf("user %q not found", username), mustJSONMsg(fmt.Sprintf("User %s not found", username))
}

func (oAdmin *OvpnAdmin) checkStaticAddressIsFree(staticAddress string, username string) bool {
	log.Infof("Static address: %s", staticAddress)

	secrets, err := oAdmin.store.ListCcdSecrets()
	if err != nil {
		log.Error(err)
		return false
	}

	for _, secret := range secrets {
		if secret.CommonName == username {
			continue
		}

		lines := strings.Split(secret.CcdContent, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, prefixStaticRoute) {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == staticAddress {
					log.Warnf("IP %s already assigned to user %s", staticAddress, secret.CommonName)
					return false
				}
			}
		}
	}

	// Audit N20: the CCD scan above only covers OTHER STATIC reservations. A
	// live client that got this same address dynamically from the VPN pool holds
	// no static CCD, so without this check we would happily pin it as a static IP
	// for another user — producing an address collision the moment OpenVPN tries
	// to place both on the tun, and mismatched per-client firewall rules. Reject
	// an address that is currently in use by a different connected client.
	for _, c := range oAdmin.snapshotActiveClients() {
		if c.CommonName == username {
			continue
		}
		if c.VirtualAddress == staticAddress {
			log.Warnf("IP %s currently in use by connected client %s (dynamic)", staticAddress, c.CommonName)
			return false
		}
	}

	return true
}
