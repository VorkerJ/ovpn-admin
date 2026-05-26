package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	if err := oAdmin.store.UpdateIndexTxtOnDisk(); err != nil {
		log.Errorln(err)
	}
	oAdmin.clients = oAdmin.usersList()

	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprint(w, string(usersList))
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprint(w, string(userStatistic))
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	userCreated, userCreateStatus := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

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
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRotate(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userDelete(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userUnrevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	if *authByPassword {
		err, msg := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"status":"error", "message": "%s"}`, msg)

		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok", "message": "%s"}`, msg)
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) {
		return nil
	} else {
		return errors.New("Имя пользователя может содержать только буквы, цифры и символы: _ . - @")
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
		o := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
		log.Debug(o)
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {

	if checkUserExist(username) {
		o := runBash(fmt.Sprintf("openvpn-user check --db.path %[1]s --user %[2]s | grep %[2]s | wc -l", *authDatabase, username))
		log.Debug(o)

		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		if strings.TrimSpace(o) == "0" {
			o = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
			log.Debug(o)
		}

		o = runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, password))
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
			o := runBash(fmt.Sprintf("openvpn-user revoke --db.path %s --user %s", *authDatabase, username))
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
			o := runBash(fmt.Sprintf("openvpn-user restore --db.path %s --user %s", *authDatabase, username))
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
			o := runBash(fmt.Sprintf("openvpn-user delete --force --db.path %s --user %s", *authDatabase, username))
			log.Debug(o)
		}

		if err := oAdmin.store.RotateClient(username, newPassword); err != nil {
			log.Error(err)
			return fmt.Errorf("error rotating user: %w", err), err.Error()
		}

		if *authByPassword {
			o := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, newPassword))
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
			_ = runBash(fmt.Sprintf("openvpn-user delete --force --db.path %s --user %s", *authDatabase, username))
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
