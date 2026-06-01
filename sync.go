package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl, oAdmin.masterHostBasicAuth, map[string]string{"X-Sync-Token": oAdmin.masterSyncToken})
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl, oAdmin.masterHostBasicAuth, map[string]string{"X-Sync-Token": oAdmin.masterSyncToken})
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func archiveCerts() {
	err := createArchiveFromDir(*easyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*ccdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

func unArchiveCerts() {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *ccdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

func ovpnUserInitDb() {
	if fi, err := os.Stat(*authDatabase); errors.Is(err, os.ErrNotExist) || fi.Size() == 0 {
		i := runBash(fmt.Sprintf("openvpn-user --db.path %[1]s db-init && openvpn-user --db.path %[1]s db-migrate", *authDatabase))
		log.Debug(i)
	}
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if _, isK8s := oAdmin.store.(*kubernetesStore); isK8s {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("X-Sync-Token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(oAdmin.masterSyncToken)) != 1 {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if _, isK8s := oAdmin.store.(*kubernetesStore); isK8s {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("X-Sync-Token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(oAdmin.masterSyncToken)) != 1 {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}
