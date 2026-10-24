//go:build !pqc
// +build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// Without the pqc build tag a PQC default fails clearly instead of falling
// back to SW.
func TestInitBCCSPPQCRequiresPQCBuild(t *testing.T) {
	home := t.TempDir()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, filepath.Join(home, "msp"), home)
	require.Error(t, err)
	require.Nil(t, csp)
	require.Contains(t, err.Error(), "requires building with the pqc tag")
}
