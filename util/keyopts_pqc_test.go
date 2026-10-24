//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func TestGetBCCSPKeyOptsMLDSA44(t *testing.T) {
	for _, ephemeral := range []bool{false, true} {
		opts, err := getBCCSPKeyOpts(&csr.KeyRequest{A: "mldsa44"}, ephemeral)
		require.NoError(t, err)
		require.IsType(t, &pqc.KeyGenOpts{}, opts)
		require.Equal(t, pqc.MLDSA44, opts.Algorithm())
		require.Equal(t, ephemeral, opts.Ephemeral())
	}
}

func TestBCCSPKeyRequestGenerateMLDSA44(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, mspDir, home)
	require.NoError(t, err)

	key, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "alice", KeyRequest: &csr.KeyRequest{A: "mldsa44"}}, csp)
	require.NoError(t, err)
	require.True(t, key.Private())
	pub, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok, "signer public key is %T", signer.Public())
	require.Equal(t, mldsa.MLDSA44(), pub.Parameters())
	_, err = os.Stat(filepath.Join(mspDir, "keystore", hex.EncodeToString(key.SKI())+"_sk"))
	require.NoError(t, err, "the key is stored as <mspDir>/keystore/<ski>_sk")

	for i := 1; i <= 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, msg, sig, nil), "signature %d does not verify with crypto/mldsa", i)
		ok, err := csp.Verify(key, sig, msg, nil)
		require.NoError(t, err)
		require.True(t, ok, "signature %d does not verify with the BCCSP", i)
	}
}

// An ECDSA or RSA request against a PQC BCCSP fails at key generation; no
// key is generated or stored.
func TestBCCSPKeyRequestGenerateClassicalWithPQCBCCSP(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, mspDir, home)
	require.NoError(t, err)

	for _, c := range []struct {
		kr      *csr.KeyRequest
		wantErr string
	}{
		{&csr.KeyRequest{A: "ecdsa", S: 256}, `unsupported PQC key-generation algorithm "ECDSAP256"`},
		{&csr.KeyRequest{A: "rsa", S: 2048}, `unsupported PQC key-generation algorithm "RSA2048"`},
		{nil, `unsupported PQC key-generation algorithm "ECDSA"`},
	} {
		key, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "alice", KeyRequest: c.kr}, csp)
		require.EqualError(t, err, c.wantErr)
		require.Nil(t, key)
		require.Nil(t, signer)
	}
	entries, _ := os.ReadDir(filepath.Join(mspDir, "keystore"))
	require.Empty(t, entries, "no key may be written")
}

// An mldsa44 request against an SW BCCSP fails; SW cannot make ML-DSA keys.
func TestBCCSPKeyRequestGenerateMLDSA44WithSWBCCSP(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")
	var opts *factory.FactoryOpts
	csp, err := InitBCCSP(&opts, mspDir, home)
	require.NoError(t, err)

	key, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "alice", KeyRequest: &csr.KeyRequest{A: "mldsa44"}}, csp)
	require.Error(t, err)
	t.Logf("SW BCCSP with mldsa44: %v", err)
	require.Nil(t, key)
	require.Nil(t, signer)
	entries, _ := os.ReadDir(filepath.Join(mspDir, "keystore"))
	require.Empty(t, entries, "no key may be written")
}
