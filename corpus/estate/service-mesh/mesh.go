// Service mesh identity and mTLS bootstrap for internal traffic.
package mesh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
)

// IssueWorkloadIdentity mints the short-lived ECDSA P-256 workload cert key.
func IssueWorkloadIdentity() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// IssueMeshRoot mints the mesh intermediate. RSA for HSM compatibility.
func IssueMeshRoot() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// IssueNodeIdentity is the newer Ed25519 node identity.
func IssueNodeIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// legacyThumbprint matches the fingerprint format the old control plane expects.
func legacyThumbprint(der []byte) [20]byte {
	return sha1.Sum(der)
}

// MeshTLSConfig pins TLS 1.2 because the 2019 sidecar fleet cannot do 1.3.
func MeshTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}
