package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
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
	if err := validateUsername(commonName); err != nil {
		return fmt.Errorf("BuildClient: %w", err)
	}
	out, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "build-client-full", commonName, "nopass")
	log.Debug(out)
	if err != nil {
		return fmt.Errorf("easyrsa build-client-full %s: %w: %s", commonName, err, out)
	}
	return nil
}

// clientStatusInIndexTxt returns the index.txt flag ("V", "R", …) for commonName,
// or "" if the CN is absent. Used to tell a benign "already revoked" from a
// genuine easyrsa revoke failure, and to look up a serial for CRL verification.
func (s *filesystemStore) clientStatusInIndexTxt(commonName string) (flag, serial string) {
	for _, u := range indexTxtParser(fRead(s.indexTxtPath)) {
		if u.DistinguishedName == "/CN="+commonName {
			return u.Flag, u.SerialNumber
		}
	}
	return "", ""
}

// crlContainsSerialHex parses the on-disk CRL and reports whether serialHex
// (as stored in index.txt) is listed as revoked. Defense-in-depth: it re-reads
// the artifact easyrsa just produced rather than trusting the exit code.
func crlContainsSerialHex(crlPath, serialHex string) (bool, error) {
	pemData, err := os.ReadFile(crlPath)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false, fmt.Errorf("no PEM block in %s", crlPath)
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return false, err
	}
	want, ok := new(big.Int).SetString(strings.TrimSpace(serialHex), 16)
	if !ok {
		return false, fmt.Errorf("invalid serial %q", serialHex)
	}
	for i := range rl.RevokedCertificateEntries {
		if rl.RevokedCertificateEntries[i].SerialNumber != nil &&
			rl.RevokedCertificateEntries[i].SerialNumber.Cmp(want) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// verifySerialInCRL asserts serialHex entered pki/crl.pem after a regen. Returns
// an error the caller must propagate so the HTTP handler reports a non-200
// instead of a false success while the cert is still valid.
func (s *filesystemStore) verifySerialInCRL(commonName, serialHex string) error {
	if serialHex == "" {
		return fmt.Errorf("verify CRL for %s: no serial found in index.txt", commonName)
	}
	crlPath := fmt.Sprintf("%s/pki/crl.pem", s.easyrsaDirPath)
	present, err := crlContainsSerialHex(crlPath, serialHex)
	if err != nil {
		return fmt.Errorf("verify CRL for %s: %w", commonName, err)
	}
	if !present {
		return fmt.Errorf("verify CRL for %s: serial %s not present in regenerated CRL", commonName, serialHex)
	}
	return nil
}

func (s *filesystemStore) RevokeClient(commonName string) error {
	// Capture the serial before the revoke changes index.txt, so we can verify
	// the CRL afterwards.
	_, serial := s.clientStatusInIndexTxt(commonName)

	// --batch suppresses the interactive "Continue with revocation: yes/no?"
	// prompt that previously required `echo yes |` shell piping.
	out, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "revoke", commonName)
	log.Debugln(out)
	if err != nil {
		// "Already revoked" is benign — proceed to regenerate the CRL so the
		// serial is (still) present. Any OTHER failure means the cert was NOT
		// revoked; abort rather than return a false success.
		if flag, _ := s.clientStatusInIndexTxt(commonName); flag == "R" {
			log.Warnf("revoke: %s already revoked, regenerating CRL: %s", commonName, out)
		} else {
			return fmt.Errorf("easyrsa revoke %s: %w: %s", commonName, err, out)
		}
	}
	out, err = runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl")
	log.Debugln(out)
	if err != nil {
		return fmt.Errorf("easyrsa gen-crl: %w: %s", err, out)
	}

	// Defense-in-depth: confirm the serial actually landed in the CRL.
	if serial != "" {
		if err := s.verifySerialInCRL(commonName, serial); err != nil {
			return err
		}
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

				// The revoked cert lives at exactly one path
				// (revoked/certs_by_serial/<serial>.crt) but must be restored to
				// TWO destinations: pki/issued/<cn>.crt AND
				// pki/certs_by_serial/<serial>.pem. Copy then delete — the
				// previous code called fMove twice with the same source, so the
				// second move silently failed because the source was already
				// gone, leaving certs_by_serial/ inconsistent.
				srcRevokedCert := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", s.easyrsaDirPath, serial)
				dstIssued := fmt.Sprintf("%s/pki/issued/%s.crt", s.easyrsaDirPath, commonName)
				dstBySerial := fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", s.easyrsaDirPath, serial)

				if err := fCopy(srcRevokedCert, dstIssued); err != nil {
					log.Errorf("UnrevokeClient: copy to issued/: %v", err)
				}
				if err := fCopy(srcRevokedCert, dstBySerial); err != nil {
					log.Errorf("UnrevokeClient: copy to certs_by_serial/: %v", err)
				}
				if err := fDelete(srcRevokedCert); err != nil {
					log.Errorf("UnrevokeClient: delete revoked cert: %v", err)
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
	// CRITICAL: revoke the cert FIRST so its serial lands in CRL. Without
	// this step the rename below leaves status=V in index.txt, gen-crl
	// generates an empty CRL, and a client holding the cert + key files
	// (which they may have downloaded earlier) can still authenticate
	// and tunnel traffic after the "delete" — defeating the whole point
	// of the operation.
	//
	// A revoke failure is only benign when the cert was ALREADY revoked. Any
	// other failure means the cert is still cryptographically valid — we must
	// NOT proceed to remove it from the UI and report success, or the user
	// keeps tunnelling with a cert that no longer appears anywhere. Distinguish
	// the two by re-reading index.txt (status "R" == already revoked).
	flag, serial := s.clientStatusInIndexTxt(commonName)
	out, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "--batch", "revoke", commonName)
	if err != nil {
		if flag == "R" {
			log.Warnf("delete: %s already revoked, proceeding with cleanup: %s", commonName, out)
		} else {
			return fmt.Errorf("delete: easyrsa revoke %s: %w: %s", commonName, err, out)
		}
	}

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
		fmt.Sprintf("%s/pki/inline/private/%s.inline", s.easyrsaDirPath, commonName),
		// CCD must die with the user. Without this, recreating a user with
		// the same CN inherits the old per-user routes (and the old fixed
		// VPN IP if it was set), which surprises operators and can route
		// the new user's traffic in unexpected directions.
		fmt.Sprintf("%s/%s", s.ccdDir, commonName),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warnf("delete: failed to remove %s: %v", path, err)
		}
	}

	if crlOut, err := runEasyrsa(s.easyrsaDirPath, s.easyrsaBinPath, "gen-crl"); err != nil {
		return fmt.Errorf("delete: easyrsa gen-crl: %w: %s", err, crlOut)
	}

	// Defense-in-depth: the deleted user's serial must now be in the CRL.
	if serial != "" {
		if err := s.verifySerialInCRL(commonName, serial); err != nil {
			return err
		}
	}

	return nil
}

func (s *filesystemStore) GetClientCert(commonName string) (cert, key string) {
	// Defence-in-depth: validate before string-concatenating into a path.
	// All current handlers already validate, but a future caller might not.
	if err := validateUsername(commonName); err != nil {
		return "", ""
	}
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
	if err := validateUsername(commonName); err != nil {
		return fmt.Errorf("SaveCcd: %w", err)
	}
	// CCD files must be world-readable: OpenVPN drops privileges to `nobody`
	// (per `user nobody` in server.conf) and reads /etc/openvpn/ccd/<CN> at
	// each client connect. The default 0600 we use for sensitive blobs makes
	// the file unreadable post-drop, which silently disables every per-user
	// push directive. 0644 is safe — CCD content is just routes/push lines,
	// not secrets.
	return os.WriteFile(s.ccdDir+"/"+commonName, data, 0o644)
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
