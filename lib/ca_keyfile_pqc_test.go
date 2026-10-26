//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/mldsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

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
	sk := newMLDSAKey(t)
	certFile, keyFile := writeCAFiles(t, t.TempDir(), sk, sk)
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

// A PQC CA given an ML-DSA certificate and a key file with another ML-DSA
// key refuses to start, before it generates or stores anything.
func TestPQCServerRefusesMismatchedMLDSACertAndKeyFiles(t *testing.T) {
	certFile, keyFile := writeCAFiles(t, t.TempDir(), newMLDSAKey(t), newMLDSAKey(t))
	srv := pqcKeyfileServer(t, freePort(t), certFile, keyFile)
	err := srv.Start()
	if err == nil {
		srv.Stop()
		require.FailNow(t, "the CA started with a mismatched certificate and key")
	}
	require.Contains(t, err.Error(), fmt.Sprintf("Invalid certificate and/or key in files '%s' and '%s': Public key and private key do not match", certFile, keyFile))
	keys, err := filepath.Glob(filepath.Join(srv.HomeDir, "msp", "keystore", "*"))
	require.NoError(t, err)
	require.Empty(t, keys, "no key was stored")
	_, err = os.Stat(filepath.Join(srv.HomeDir, "ca-cert.pem"))
	require.True(t, os.IsNotExist(err), "no root was generated")
}
