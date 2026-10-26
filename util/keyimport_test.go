/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeMLDSAKeyFile writes sk as a PKCS#8 "PRIVATE KEY" PEM file, the form
// cryptogen writes, and returns its path.
func writeMLDSAKeyFile(t *testing.T, sk *mldsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "priv_sk")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return p
}

// A classical BCCSP refuses an ML-DSA key with an error that names the PQC
// BCCSP, in every build.
func TestImportMLDSAKeyIntoSWBCCSP(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	keyFile := writeMLDSAKeyFile(t, sk)
	for _, temporary := range []bool{true, false} {
		key, err := ImportBCCSPKeyFromPEM(keyFile, GetDefaultBCCSP(), temporary)
		require.EqualError(t, err, "Failed to import ML-DSA private key for '"+keyFile+"': ML-DSA private keys need the PQC BCCSP: build with -tags pqc and set bccsp.default to PQC")
		require.Nil(t, key)
	}
}

// ECDSA import into the SW BCCSP and the RSA refusal are unchanged.
func TestImportClassicalKeysIntoSWBCCSP(t *testing.T) {
	csp := GetDefaultBCCSP()
	key, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), csp, true)
	require.NoError(t, err)
	require.True(t, key.Private())
	cert, err := GetX509CertificateFromPEMFile(filepath.Join("testdata", "ec.pem"))
	require.NoError(t, err)
	pub, err := key.PublicKey()
	require.NoError(t, err)
	der, err := pub.Bytes()
	require.NoError(t, err)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, der, "the imported key matches ec.pem")

	rsaFile := filepath.Join("testdata", "rsa-key.pem")
	key, err = ImportBCCSPKeyFromPEM(rsaFile, csp, true)
	require.EqualError(t, err, "Failed to import RSA key from "+rsaFile+"; RSA private key import is not supported")
	require.Nil(t, key)
}
