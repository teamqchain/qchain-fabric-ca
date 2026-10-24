//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// A PQC default with no pqc section initializes, and keys land in the
// default keystore.
func TestInitBCCSPPQCWithoutPQCSection(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, mspDir, home)
	require.NoError(t, err)

	k, err := csp.KeyGen(&pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44})
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(mspDir, "keystore", hex.EncodeToString(k.SKI())+"_sk"))
	require.NoError(t, err, "the ML-DSA private key is stored in <mspDir>/keystore")
}
