//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// writeMLDSACAFiles writes a self-signed ML-DSA-44 CA certificate and its
// PKCS#8 key to dir, as cryptogen lays out a CA (<name>-cert.pem, priv_sk).
func writeMLDSACAFiles(t *testing.T, dir string, sk *mldsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "ca.org1.example.com", Organization: []string{"org1.example.com"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, sk.PublicKey(), sk)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	certFile, keyFile = filepath.Join(dir, "ca.org1.example.com-cert.pem"), filepath.Join(dir, "priv_sk")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

// pqcKeyfileServer returns a PQC CA configured with ca.certfile and
// ca.keyfile.
func pqcKeyfileServer(t *testing.T, port int, certFile, keyFile string) *Server {
	srv := getServer(port, t.TempDir(), "", -1, t)
	require.NotNil(t, srv)
	srv.CA.Config.CSP = &factory.FactoryOpts{Default: "PQC"}
	srv.CA.Config.CA.Certfile = certFile
	srv.CA.Config.CA.Keyfile = keyFile
	return srv
}

// A PQC CA started with an external ML-DSA certificate and key uses that
// certificate as its root, stores the imported key as <ski>_sk, and issues
// certificates that chain to it.
func TestPQCServerStartsWithMLDSACertAndKeyFiles(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	certFile, keyFile := writeMLDSACAFiles(t, t.TempDir(), sk)
	rootPEM, err := os.ReadFile(certFile)
	require.NoError(t, err)
	root := readCert(t, rootPEM)

	srv := startTestServer(t, func(port int) *Server { return pqcKeyfileServer(t, port, certFile, keyFile) })

	after, err := os.ReadFile(certFile)
	require.NoError(t, err)
	require.Equal(t, rootPEM, after, "the configured certificate is used, not replaced")
	_, err = os.Stat(filepath.Join(srv.HomeDir, "ca-cert.pem"))
	require.True(t, os.IsNotExist(err), "no root of its own was generated")
	keys, err := filepath.Glob(filepath.Join(srv.HomeDir, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	rootKey, err := srv.CA.csp.KeyImport(root, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(rootKey.SKI())+"_sk", filepath.Base(keys[0]), "the imported key is stored under the root key's SKI")

	resp := pqcEnroll(t, fmt.Sprintf("http://localhost:%d", srv.Config.Port), "admin", "adminpw", nil)
	leaf := readCert(t, resp.Identity.GetECert().Cert())
	require.IsType(t, &mldsa.PublicKey{}, leaf.PublicKey)
	require.NoError(t, leaf.CheckSignatureFrom(root), "the leaf chains to the configured root")
	require.Equal(t, root.SubjectKeyId, leaf.AuthorityKeyId)
	require.Equal(t, root.RawSubject, leaf.RawIssuer)
}
