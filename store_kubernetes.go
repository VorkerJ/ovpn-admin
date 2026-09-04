package main

import (
	"ovpn-admin/internal/storage"
)

// kubernetesStore adapts the existing OpenVPNPKI (Kubernetes secrets) to the
// storage.Store interface.
type kubernetesStore struct {
	pki *OpenVPNPKI
}

// compile-time check
var _ storage.Store = (*kubernetesStore)(nil)

func (s *kubernetesStore) BuildClient(commonName string) error {
	return s.pki.easyrsaBuildClient(commonName)
}

func (s *kubernetesStore) RevokeClient(commonName string) error {
	return s.pki.easyrsaRevoke(commonName)
}

func (s *kubernetesStore) UnrevokeClient(commonName string) error {
	return s.pki.easyrsaUnrevoke(commonName)
}

func (s *kubernetesStore) RotateClient(commonName, newPassword string) error {
	return s.pki.easyrsaRotate(commonName, newPassword)
}

func (s *kubernetesStore) DeleteClient(commonName string) error {
	return s.pki.easyrsaDelete(commonName)
}

func (s *kubernetesStore) GetClientCert(commonName string) (cert, key string) {
	return s.pki.easyrsaGetClientCert(commonName)
}

func (s *kubernetesStore) UpdateIndexTxtOnDisk() error {
	return s.pki.updateIndexTxtOnDisk()
}

func (s *kubernetesStore) GetCcd(commonName string) string {
	return s.pki.secretGetCcd(commonName)
}

func (s *kubernetesStore) SaveCcd(commonName string, data []byte) error {
	return s.pki.secretUpdateCcd(commonName, data)
}

func (s *kubernetesStore) ListCcdSecrets() ([]storage.CcdSecret, error) {
	secrets, err := s.pki.secretsGetByLabels("index.txt=,type=clientAuth")
	if err != nil {
		return nil, err
	}

	var result []storage.CcdSecret
	for _, secret := range secrets.Items {
		ccd := secret.Data["ccd"]
		if len(ccd) == 0 {
			continue
		}
		result = append(result, storage.CcdSecret{
			CommonName: secret.Labels["name"],
			CcdContent: string(ccd),
		})
	}
	return result, nil
}

func (s *kubernetesStore) LoadCommonRoutes() ([]byte, error) {
	return s.pki.secretGetCommonRoutes()
}

func (s *kubernetesStore) SaveCommonRoutes(data []byte) error {
	return s.pki.secretUpdateCommonRoutes(data)
}

func (s *kubernetesStore) LoadServerConfig() ([]byte, error) {
	return s.pki.secretGetServerConfig()
}

func (s *kubernetesStore) SaveServerConfig(data []byte) error {
	return s.pki.secretUpdateServerConfig(data)
}
