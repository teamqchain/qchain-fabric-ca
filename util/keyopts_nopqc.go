//go:build !pqc
// +build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/mldsa"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/pkg/errors"
)

// mldsa44KeyGenOpts fails: ML-DSA keys need the PQC BCCSP, which is only
// built with the pqc tag.
func mldsa44KeyGenOpts(bool) (bccsp.KeyGenOpts, error) {
	return nil, errors.New("key algorithm mldsa44 requires a build with -tags pqc")
}

// importMLDSAPrivateKey fails: ML-DSA keys need the PQC BCCSP, which is
// only built with the pqc tag.
func importMLDSAPrivateKey(bccsp.BCCSP, *mldsa.PrivateKey, bool) (bccsp.Key, error) {
	return nil, errMLDSAKeyNeedsPQC
}
