//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// A classical (ECDSA) CA refuses an ML-DSA CSR through the real enroll path.
func TestClassicalCARefusesMLDSACSR(t *testing.T) {
	_, url := startKeyFamilyServer(t, nil)
	pqcClient := &Client{HomeDir: t.TempDir(), Config: &ClientConfig{URL: url, CSP: &factory.FactoryOpts{Default: "PQC"}}}
	cert, err := enrollAdmin(t, url, nil, pqcClient) // default key request: mldsa44
	require.Error(t, err)
	require.Nil(t, cert)
	require.Contains(t, err.Error(), "CSR public key algorithm ML-DSA does not match the CA certificate's ECDSA key: a CA only signs requests with the same key family (ML-DSA vs classical)")
}
