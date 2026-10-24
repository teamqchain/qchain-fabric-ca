/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func TestGetKeyRequestPQCDefault(t *testing.T) {
	for _, csp := range []*factory.FactoryOpts{
		{Default: "PQC"},
		{Default: "pqc"},
		// The default template has an sw section; a PQC default still wins.
		{Default: "PQC", SW: &factory.SwOpts{Hash: "SHA2", Security: 384}},
	} {
		kr := GetKeyRequest(&CAConfig{CSP: csp})
		require.Equal(t, &api.KeyRequest{Algo: "mldsa44"}, kr, "bccsp.default %q", csp.Default)
	}
}

func TestGetKeyRequestClassicalUnchanged(t *testing.T) {
	kr := GetKeyRequest(&CAConfig{CSP: &factory.FactoryOpts{Default: "SW", SW: &factory.SwOpts{Hash: "SHA2", Security: 384}}})
	require.Equal(t, &api.KeyRequest{Algo: "ecdsa", Size: 384}, kr)

	kr = GetKeyRequest(&CAConfig{CSP: &factory.FactoryOpts{}})
	require.Equal(t, api.NewKeyRequest(), kr, "no SW options: cfssl's default ECDSA P-256 request")
	require.Equal(t, &api.KeyRequest{Algo: "ecdsa", Size: 256}, kr)
}

// A classical config with no bccsp block: ConfigureBCCSP makes it SW, the
// key request is ECDSA P-256, and the generated key is ECDSA P-256.
func TestGetKeyRequestNoBCCSPBlockIsECDSA(t *testing.T) {
	home := t.TempDir()
	cfg := &CAConfig{}
	require.Nil(t, cfg.CSP)
	csp, err := util.InitBCCSP(&cfg.CSP, "", home)
	require.NoError(t, err)
	require.Equal(t, "SW", cfg.CSP.Default)

	kr := GetKeyRequest(cfg)
	require.Equal(t, &api.KeyRequest{Algo: "ecdsa", Size: 256}, kr)

	_, signer, err := util.BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "ca", KeyRequest: &csr.KeyRequest{A: kr.Algo, S: kr.Size}}, csp)
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "signer public key is %T", signer.Public())
	require.Equal(t, elliptic.P256(), pub.Curve)
}
