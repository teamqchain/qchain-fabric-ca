/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// bccsp.default must be PQC in upper case, in every build: fabric-ca's own
// configuration treats "pqc" as PQC, but the BCCSP factory has no "pqc"
// provider.
func TestInitBCCSPLowerCasePQC(t *testing.T) {
	opts := &factory.FactoryOpts{Default: "pqc"}
	csp, err := InitBCCSP(&opts, "", t.TempDir())
	require.EqualError(t, err, "Failed to get BCCSP with opts: Could not find BCCSP, no 'pqc' provider")
	require.Nil(t, csp)
}
