package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"ovpn-admin/internal/storage"
)

// runEasyrsa invokes the easyrsa binary directly via exec.Command, with the
// working directory set to easyrsaDirPath. Arguments are passed as argv, so
// shell metacharacters in commonName cannot lead to command injection — unlike
// the legacy runBash path that interpolated into a `cd && easyrsa ...` shell
// script.
func runEasyrsa(workDir, easyrsaBin string, args ...string) (string, error) {
	cmd := exec.Command(easyrsaBin, args...)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// filesystemStore adapts the existing easyrsa CLI + flat-file operations to the
// storage.Store interface.
type filesystemStore struct {
	easyrsaDirPath string
	easyrsaBinPath string
	ccdDir         string
	indexTxtPath   string
}

// compile-time check
var _ storage.Store = (*filesystemStore)(nil)

func (s *filesystemStore) BuildClient(commonName string) error {
	out, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "build-client-full", commonName, "nopass")
	log.Debug(out)
	if err != nil {
		return fmt.Errorf("easyrsa build-client-full %s: %w: %s", commonName, err, out)
	}
	return nil
}

func (s *filesystemStore) RevokeClient(commonName string) error {
	// --batch suppresses the interactive "Continue with revocation: yes/no?"
	// prompt that previously required `echo yes |` shell piping.
	out, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "revoke", commonName)
	log.Debugln(out)
	if err != nil {
		return fmt.Errorf("easyrsa revoke %s: %w: %s", commonName, err, out)
	}
	out, err = runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl")
	log.Debugln(out)
	if err != nil {
		return fmt.Errorf("easyrsa gen-crl: %w: %s", err, out)
	}
	return nil
}

func (s *filesystemStore) UnrevokeClient(commonName string) error {
	usersFromIndexTxt := indexTxtParser(fRead(s.indexTxtPath))
	for i := range usersFromIndexTxt {
		if usersFromIndexTxt[i].DistinguishedName == "/CN="+commonName {
			if usersFromIndexTxt[i].Flag == "R" {
				usersFromIndexTxt[i].Flag = "V"
				usersFromIndexTxt[i].RevocationDate = ""

				serial := usersFromIndexTxt[i].SerialNumber

				if err := fMove(
					fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", s.easyrsaDirPath, serial),
					fmt.Sprintf("%s/pki/issued/%s.crt", s.easyrsaDirPath, commonName),
				); err != nil {
					log.Error(err)
				}
				if err := fMove(
					fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", s.easyrsaDirPath, serial),
					fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", s.easyrsaDirPath, serial),
				); err != nil {
					log.Error(err)
				}
				if err := fMove(
					fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", s.easyrsaDirPath, serial),
					fmt.Sprintf("%s/pki/private/%s.key", s.easyrsaDirPath, commonName),
				); err != nil {
					log.Error(err)
				}
				if err := fMove(
					fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", s.easyrsaDirPath, serial),
					fmt.Sprintf("%s/pki/reqs/%s.req", s.easyrsaDirPath, commonName),
				); err != nil {
					log.Error(err)
				}

				if err := fWrite(s.indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
					log.Error(err)
				}

				if crlOut, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl"); err != nil {
					log.Warnf("unrevoke: easyrsa gen-crl: %v: %s", err, crlOut)
				}

				break
			}
		}
	}

	// Write final state (covers the case where nothing was revoked — still safe).
	if err := fWrite(s.indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
		log.Error(err)
	}
	return nil
}

func (s *filesystemStore) RotateClient(commonName, newPassword string) error {
	var oldUserIndex, newUserIndex int
	var oldUserSerial string

	uniqHash := strings.ReplaceAll(uuid.New().String(), "-", "")

	// 1. Rename the old entry in index.txt
	usersFromIndexTxt := indexTxtParser(fRead(s.indexTxtPath))
	for i := range usersFromIndexTxt {
		if usersFromIndexTxt[i].DistinguishedName == "/CN="+commonName {
			oldUserSerial = usersFromIndexTxt[i].SerialNumber
			usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + commonName + "-" + uniqHash
			oldUserIndex = i
			break
		}
	}
	if err := fWrite(s.indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
		return fmt.Errorf("rotate: write index.txt after rename: %w", err)
	}

	// 2. Remove old PKI files so easyrsa can regenerate them
	for _, path := range []string{
		fmt.Sprintf("%s/pki/private/%s.key", s.easyrsaDirPath, commonName),
		fmt.Sprintf("%s/pki/issued/%s.crt", s.easyrsaDirPath, commonName),
		fmt.Sprintf("%s/pki/reqs/%s.req", s.easyrsaDirPath, commonName),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warnf("rotate: failed to remove %s: %v", path, err)
		}
	}

	// 3. Build a new certificate (PKI only — no openvpn-user password handling)
	out, buildErr := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "build-client-full", commonName, "nopass")
	log.Debug(out)
	if buildErr != nil {
		return fmt.Errorf("rotate: easyrsa build-client-full %s: %w: %s", commonName, buildErr, out)
	}

	// 4. Swap old and new entries so the new cert occupies the old position
	usersFromIndexTxt = indexTxtParser(fRead(s.indexTxtPath))
	for i := range usersFromIndexTxt {
		if usersFromIndexTxt[i].DistinguishedName == "/CN="+commonName {
			newUserIndex = i
		}
		if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
			oldUserIndex = i
		}
	}
	usersFromIndexTxt[oldUserIndex], usersFromIndexTxt[newUserIndex] = usersFromIndexTxt[newUserIndex], usersFromIndexTxt[oldUserIndex]

	if err := fWrite(s.indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
		return fmt.Errorf("rotate: write index.txt after swap: %w", err)
	}

	// 5. Regenerate CRL
	if crlOut, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl"); err != nil {
		log.Warnf("rotate: easyrsa gen-crl: %v: %s", err, crlOut)
	}

	return nil
}

func (s *filesystemStore) DeleteClient(commonName string) error {
	uniqHash := strings.ReplaceAll(uuid.New().String(), "-", "")

	usersFromIndexTxt := indexTxtParser(fRead(s.indexTxtPath))
	for i := range usersFromIndexTxt {
		if usersFromIndexTxt[i].DistinguishedName == "/CN="+commonName {
			usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + commonName + "-" + uniqHash
			break
		}
	}

	if err := fWrite(s.indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
		log.Error(err)
	}

	for _, path := range []string{
		fmt.Sprintf("%s/pki/private/%s.key", s.easyrsaDirPath, commonName),
		fmt.Sprintf("%s/pki/issued/%s.crt", s.easyrsaDirPath, commonName),
		fmt.Sprintf("%s/pki/reqs/%s.req", s.easyrsaDirPath, commonName),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warnf("delete: failed to remove %s: %v", path, err)
		}
	}

	if crlOut, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl"); err != nil {
		log.Warnf("delete: easyrsa gen-crl: %v: %s", err, crlOut)
	}

	return nil
}

func (s *filesystemStore) GetClientCert(commonName string) (cert, key string) {
	cert = fRead(s.easyrsaDirPath + "/pki/issued/" + commonName + ".crt")
	key = fRead(s.easyrsaDirPath + "/pki/private/" + commonName + ".key")
	return
}

func (s *filesystemStore) UpdateIndexTxtOnDisk() error {
	// For the filesystem backend, index.txt is already on disk — nothing to sync.
	return nil
}

func (s *filesystemStore) GetCcd(commonName string) string {
	path := s.ccdDir + "/" + commonName
	if !fExist(path) {
		return ""
	}
	return fRead(path)
}

func (s *filesystemStore) SaveCcd(commonName string, data []byte) error {
	return fWrite(s.ccdDir+"/"+commonName, string(data))
}

func (s *filesystemStore) ListCcdSecrets() ([]storage.CcdSecret, error) {
	entries, err := os.ReadDir(s.ccdDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []storage.CcdSecret
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip internal config blobs stored alongside CCD files.
		if strings.HasPrefix(name, "_") {
			continue
		}
		content := fRead(s.ccdDir + "/" + name)
		if content == "" {
			continue
		}
		result = append(result, storage.CcdSecret{
			CommonName: name,
			CcdContent: content,
		})
	}
	return result, nil
}

func (s *filesystemStore) LoadCommonRoutes() ([]byte, error) {
	path := s.ccdDir + "/_common_routes.json"
	if !fExist(path) {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *filesystemStore) SaveCommonRoutes(data []byte) error {
	path := s.ccdDir + "/_common_routes.json"
	return writeFileAtomic(path, data)
}

func (s *filesystemStore) LoadServerConfig() ([]byte, error) {
	path := s.ccdDir + "/_server_config.json"
	if !fExist(path) {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *filesystemStore) SaveServerConfig(data []byte) error {
	path := s.ccdDir + "/_server_config.json"
	return writeFileAtomic(path, data)
}

func (s *filesystemStore) Bootstrap() error {
	// Filesystem backend requires no bootstrap — easyrsa and CCD dirs are
	// managed externally.
	return nil
}
