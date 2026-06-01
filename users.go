package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

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

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	// Storage refresh failures should not block the response — the cached
	// client list is still useful for read-only display and panicking would
	// log out the admin for no actionable reason.
	if err := oAdmin.store.UpdateIndexTxtOnDisk(); err != nil {
		log.Errorf("userListHandler: UpdateIndexTxtOnDisk: %v", err)
	}
	oAdmin.clients = oAdmin.usersList()
	if oAdmin.clients == nil {
		oAdmin.clients = []OpenvpnClient{}
	}

	w.Header().Set("Content-Type", "application/json")
	usersList, err := json.Marshal(oAdmin.clients)
	if err != nil {
		log.Errorf("userListHandler: marshal: %v", err)
		fmt.Fprint(w, "[]")
		return
	}
	fmt.Fprint(w, string(usersList))
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(req.Username))
	fmt.Fprint(w, string(userStatistic))
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	// Гейт: если модуль server-config включён и admin ещё не сохранял
	// настройки через UI — блокируем создание (defaults на диске нужны
	// только чтобы openvpn-сервер стартовал, это не означает что admin
	// согласен с этими параметрами).
	if oAdmin.serverConfigStore != nil && !oAdmin.serverConfigStore.snapshot().Initialized {
		http.Error(w, `{"error":"server not initialized — configure server in UI first"}`, http.StatusPreconditionFailed)
		return
	}
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	userCreated, userCreateStatus := oAdmin.userCreate(req.Username, req.Password)

	if userCreated {
		oAdmin.clients = oAdmin.usersList()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	// Ротация выпускает новый сертификат, поэтому блокируется тем же
	// гейтом что и создание пользователя.
	if oAdmin.serverConfigStore != nil && !oAdmin.serverConfigStore.snapshot().Initialized {
		http.Error(w, `{"error":"server not initialized — configure server in UI first"}`, http.StatusPreconditionFailed)
		return
	}
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	err, msg := oAdmin.userRotate(req.Username, req.Password)
	if err != nil {
		log.Errorf("userRotate: %v", err)
		http.Error(w, `{"error":"failed to rotate user"}`, http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	err, msg := oAdmin.userDelete(req.Username)
	if err != nil {
		log.Errorf("userDelete: %v", err)
		http.Error(w, `{"error":"failed to delete user"}`, http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	err, msg := oAdmin.userRevoke(req.Username)
	if err != nil {
		log.Errorf("userRevoke: %v", err)
		http.Error(w, `{"error":"failed to revoke user"}`, http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	err, msg := oAdmin.userUnrevoke(req.Username)
	if err != nil {
		log.Errorf("userUnrevoke: %v", err)
		http.Error(w, `{"error":"failed to unrevoke user"}`, http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var req usernamePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if *authByPassword {
		err, msg := oAdmin.userChangePassword(req.Username, req.Password)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			log.Errorf("userChangePassword: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": msg,
			})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ok",
				"message": msg,
			})
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(req.Username))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var req usernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	// 	fmt.Fprintf(w, "%s", userDisconnect(req.Username))
	fmt.Fprintf(w, "%s", req.Username)
}

func validateUsername(username string) error {
	if username == "" || username == "." || username == ".." {
		return errors.New("Имя пользователя не может быть пустым или состоять только из точек")
	}
	if strings.Contains(username, "/") || strings.Contains(username, "\\") {
		return errors.New("Имя пользователя не может содержать слэши")
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
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if checkUserExist(username) {
		ucErr = fmt.Sprintf("Пользователь \"%s\" уже существует\n", username)
		log.Debugf("userCreate: checkUserExist():  %s", ucErr)
		return false, ucErr
	}

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error()
	}

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error()
		}
	}

	if err := oAdmin.store.BuildClient(username); err != nil {
		log.Error(err)
	}

	if *authByPassword {
		o := runOpenvpnUser("create", "--db.path", *authDatabase, "--user", username, "--password", password)
		log.Debug(o)
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

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

	return fmt.Errorf("User \"%s\" not found}", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
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
	return fmt.Errorf("User \"%s\" not found}", username), fmt.Sprintf("User \"%s\" not found", username)
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
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
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
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
	}
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	if checkUserExist(username) {
		if *authByPassword {
			_ = runOpenvpnUser("delete", "--force", "--db.path", *authDatabase, "--user", username)
		}

		if err := oAdmin.store.DeleteClient(username); err != nil {
			log.Error(err)
		}

		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
	}
	return fmt.Errorf("User \"%s\" not found}", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
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
