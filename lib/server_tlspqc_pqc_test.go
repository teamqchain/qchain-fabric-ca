//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// With a PQC BCCSP the server's TLS load path (util.LoadX509KeyPair, as in
// listenAndServe) still loads an external ECDSA certificate and key, via its
// tls.LoadX509KeyPair fallback.
func TestPQCServerLoadsExternalECDSATLSKeyPair(t *testing.T) {
	home := t.TempDir()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := util.InitBCCSP(&opts, "", home)
	require.NoError(t, err)

	certFile, keyFile := writeECDSATLSFiles(t, t.TempDir())
	cer, err := util.LoadX509KeyPair(certFile, keyFile, csp)
	require.NoError(t, err)
	require.Len(t, cer.Certificate, 1)
	_, ok := cer.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "TLS private key is %T", cer.PrivateKey)
	leaf, err := x509.ParseCertificate(cer.Certificate[0])
	require.NoError(t, err)
	_, ok = leaf.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	// Loading did not put anything in the PQC keystore.
	ks, _ := filepath.Glob(filepath.Join(home, "msp", "keystore", "*"))
	require.Empty(t, ks)
}
