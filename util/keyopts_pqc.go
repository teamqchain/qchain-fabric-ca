//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"github.com/hyperledger/fabric-lib-go/bccsp"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
)

// mldsa44KeyGenOpts returns the PQC BCCSP options for an ML-DSA-44 key.
func mldsa44KeyGenOpts(ephemeral bool) (bccsp.KeyGenOpts, error) {
	return &pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44, Temporary: ephemeral}, nil
}
