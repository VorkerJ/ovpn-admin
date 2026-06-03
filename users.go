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
	log.Debug(runOpenvpnUser("--db.path", *authDatabase, "db-init"))
	log.Debug(runOpenvpnUser("--db.path", *authDatabase, "db-migrate"))
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

func runOpenvpnUser(args ...string) string {
	cmd := exec.Command("openvpn-user", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Redact --password values from logged args.
		// NOTE: this only protects log streams; the password is still visible in
		// `ps aux` while the subprocess runs because openvpn-user takes the
		// password as an argv flag. Migrating to stdin/env requires upstream
		// support that we cannot verify here.
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
	return strings.TrimSpace(string(out))
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
	if err := validateUsername(req.Username); err != nil {
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
	if err := validateUsername(req.Username); err != nil {
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
	if err := validateUsername(req.Username); err != nil {
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
	if err := validateUsername(req.Username); err != nil {
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
	if err := validateUsername(req.Username); err != nil {
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
	if !*authByPassword {
		writeJSONError(w, http.StatusNotImplemented, "password auth disabled")
		return
	}
	if err := validateUsername(req.Username); err != nil {
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

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateUsername(req.Username); err != nil {
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

	if err := validateUsername(req.Username); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	if !checkUserExist(req.Username) {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	connected, connections := isUserConnected(req.Username, oAdmin.activeClients)
	if !connected {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "disconnected": 0})
		return
	}

	for _, conn := range connections {
		oAdmin.mgmtKillUserConnection(req.Username, conn)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "disconnected": len(connections)})
}

func validateUsername(username string) error {
	if username == "" || username == "." || username == ".." {
		return errors.New("Имя пользователя не может быть пустым или состоять только из точек")
	}
	if strings.Contains(username, "/") || strings.Contains(username, "\\") {
		return errors.New("Имя пользователя не может содержать слэши")
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

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error()
		}
	}

	if err := oAdmin.store.BuildClient(username); err != nil {
		log.Errorf("userCreate: BuildClient failed for %s: %v", username, err)
		return false, fmt.Sprintf("Не удалось создать сертификат: %v", err)
	}

	if *authByPassword {
		o := runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", password)
		log.Debug(o)
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

	if checkUserExist(username) {
		o := runOpenvpnUser("check", "--db.path", *authDatabase, "--user", username)
		log.Debug(o)

		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		if !strings.Contains(o, username) {
			o = runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", password)
			log.Debug(o)
		}

		o = runOpenvpnUser("change-password", "--db.path", *authDatabase, "--user", username, "--password", password)
		log.Debug(o)

		log.Infof("Password for user %s was changed", username)

		return nil, "Password changed"
	}

	return fmt.Errorf("user %q not found", username), mustJSONMsg(fmt.Sprintf("User %s not found", username))
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.activeClients {
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
			log.Error(err)
		}

		if *authByPassword {
			o := runOpenvpnUser("revoke", "--db.path", *authDatabase, "--user", username)
			log.Debug(o)
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
		log.Tracef("User %s connected: %t", username, userConnected)
		if userConnected {
			for _, connection := range userConnectedTo {
				oAdmin.mgmtKillUserConnection(username, connection)
				log.Infof("Session for user \"%s\" killed", username)
			}
		}

		oAdmin.setState()
		return nil, fmt.Sprintf("user \"%s\" revoked", username)
	}
	log.Infof("user \"%s\" not found", username)
	return fmt.Errorf("user %q not found", username), fmt.Sprintf("User %s not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	if checkUserExist(username) {
		if err := oAdmin.store.UnrevokeClient(username); err != nil {
			log.Error(err)
		}

		if *authByPassword {
			o := runOpenvpnUser("restore", "--db.path", *authDatabase, "--user", username)
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
		if *authByPassword {
			o := runOpenvpnUser("delete", "--force", "--db.path", *authDatabase, "--user", username)
			log.Debug(o)
		}

		if err := oAdmin.store.RotateClient(username, newPassword); err != nil {
			log.Error(err)
			return fmt.Errorf("error rotating user: %w", err), err.Error()
		}

		if *authByPassword {
			o := runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", newPassword)
			log.Debug(o)
		}

		crlFix()
		oAdmin.updateClients()
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
		// not on already-established sessions.
		connectedUsers := oAdmin.mgmtGetActiveClients()
		connected, connections := isUserConnected(username, connectedUsers)
		if connected {
			for _, conn := range connections {
				oAdmin.mgmtKillUserConnection(username, conn)
			}
		}

		if *authByPassword {
			_ = runOpenvpnUser("delete", "--force", "--db.path", *authDatabase, "--user", username)
		}

		if err := oAdmin.store.DeleteClient(username); err != nil {
			log.Error(err)
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

	return true
}
