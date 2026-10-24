//go:build !pqc
// +build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// Without the pqc build tag an mldsa44 request fails clearly and never
// falls back to an ECDSA key.
func TestGetBCCSPKeyOptsMLDSA44RequiresPQCBuild(t *testing.T) {
	_, err := getBCCSPKeyOpts(&csr.KeyRequest{A: "mldsa44"}, false)
	require.EqualError(t, err, "key algorithm mldsa44 requires a build with -tags pqc")

	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")
	var opts *factory.FactoryOpts
	csp, err := InitBCCSP(&opts, mspDir, home)
	require.NoError(t, err)
	key, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "alice", KeyRequest: &csr.KeyRequest{A: "mldsa44"}}, csp)
	require.EqualError(t, err, "key algorithm mldsa44 requires a build with -tags pqc")
	require.Nil(t, key)
	require.Nil(t, signer)
	entries, _ := os.ReadDir(filepath.Join(mspDir, "keystore"))
	require.Empty(t, entries, "no ECDSA key may be generated instead")
}
