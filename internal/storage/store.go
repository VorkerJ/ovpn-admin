package storage

// Store abstracts persistence operations across storage backends
// (filesystem via easyrsa, kubernetes.secrets). Every call site that
// previously checked `if *storageBackend == "kubernetes.secrets"` now
// calls a Store method instead.
type Store interface {
	// PKI / certificate operations
	BuildClient(commonName string) error
	RevokeClient(commonName string) error
	UnrevokeClient(commonName string) error
	RotateClient(commonName, newPassword string) error
	DeleteClient(commonName string) error
	GetClientCert(commonName string) (cert, key string)
	UpdateIndexTxtOnDisk() error

	// CCD (Client Config Directory)
	GetCcd(commonName string) string
	SaveCcd(commonName string, data []byte) error
	ListCcdSecrets() ([]CcdSecret, error)

	// Config blobs (common-routes, server-config)
	LoadCommonRoutes() ([]byte, error)
	SaveCommonRoutes(data []byte) error
	LoadServerConfig() ([]byte, error)
	SaveServerConfig(data []byte) error
}

// CcdSecret holds per-client CCD content, used by checkStaticAddressIsFree
// to scan all clients for address collisions.
type CcdSecret struct {
	CommonName string
	CcdContent string
}
