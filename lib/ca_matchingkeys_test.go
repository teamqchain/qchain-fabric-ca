/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeCAFiles writes a self-signed CA certificate for certKey and the
// PKCS#8 key keyFileKey to dir, as cryptogen lays out a CA (<name>-cert.pem,
// priv_sk). certKey and keyFileKey differ to make a mismatched pair.
func writeCAFiles(t *testing.T, dir string, certKey, keyFileKey crypto.Signer) (certFile, keyFile string) {
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
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, certKey.Public(), certKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(keyFileKey)
	require.NoError(t, err)
	certFile, keyFile = filepath.Join(dir, "ca.org1.example.com-cert.pem"), filepath.Join(dir, "priv_sk")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

// checkMatchingKeys runs validateMatchingKeys on a CA certificate for
// certKey and a key file holding keyFileKey.
func checkMatchingKeys(t *testing.T, certKey, keyFileKey crypto.Signer) error {
	t.Helper()
	certFile, keyFile := writeCAFiles(t, t.TempDir(), certKey, keyFileKey)
	cert, err := getCertFromFile(certFile)
	require.NoError(t, err)
	return validateMatchingKeys(cert, keyFile)
}

func newMLDSAKey(t *testing.T) *mldsa.PrivateKey {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	return k
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// ML-DSA certificates and keys are compared in every build.
func TestValidateMatchingKeysMLDSA(t *testing.T) {
	a, b := newMLDSAKey(t), newMLDSAKey(t)
	require.NoError(t, checkMatchingKeys(t, a, a), "matching pair")
	require.EqualError(t, checkMatchingKeys(t, a, b), "Public key and private key do not match", "certificate from key A, key file B")
	require.EqualError(t, checkMatchingKeys(t, a, newECDSAKey(t)),
		"Public key and private key do not match: the certificate has an ML-DSA key and the private key is *ecdsa.PrivateKey")
}

// Classical behavior is unchanged: ECDSA is compared, an ECDSA certificate
// with an ML-DSA key file fails to parse the key as ECDSA, and other key
// types such as Ed25519 are still not checked.
func TestValidateMatchingKeysClassicalUnchanged(t *testing.T) {
	a, b := newECDSAKey(t), newECDSAKey(t)
	require.NoError(t, checkMatchingKeys(t, a, a))
	require.EqualError(t, checkMatchingKeys(t, a, b), "Public key and private key do not match")
	require.Error(t, checkMatchingKeys(t, a, newMLDSAKey(t)))

	_, edA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, edB, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, checkMatchingKeys(t, edA, edB), "Ed25519 pairs are not checked, as before")
}
