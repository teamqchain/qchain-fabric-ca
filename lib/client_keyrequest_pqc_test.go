//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/mldsa"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// The client's default key request generates an ML-DSA-44 key with a PQC
// BCCSP; an explicit ECDSA request still fails clearly at key generation.
func TestClientDefaultKeyRequestGeneratesMLDSA44(t *testing.T) {
	home := t.TempDir()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := util.InitBCCSP(&opts, filepath.Join(home, "msp"), home)
	require.NoError(t, err)
	c := clientWithBCCSP(opts)

	_, signer, err := util.BCCSPKeyRequestGenerate(c.newCertificateRequest(nil, "alice"), csp)
	require.NoError(t, err)
	pub, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok, "signer public key is %T", signer.Public())
	require.Equal(t, mldsa.MLDSA44(), pub.Parameters())

	explicit := c.newCertificateRequest(&api.CSRInfo{KeyRequest: &api.KeyRequest{Algo: "ecdsa", Size: 256}}, "alice")
	_, _, err = util.BCCSPKeyRequestGenerate(explicit, csp)
	require.EqualError(t, err, `unsupported PQC key-generation algorithm "ECDSAP256"`)
}
