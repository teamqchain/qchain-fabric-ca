//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/mldsa"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/pkg/errors"
)

// mldsa44KeyGenOpts returns the PQC BCCSP options for an ML-DSA-44 key.
func mldsa44KeyGenOpts(ephemeral bool) (bccsp.KeyGenOpts, error) {
	return &pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44, Temporary: ephemeral}, nil
}

// importMLDSAPrivateKey imports an ML-DSA-44 private key into csp, which
// must be the PQC BCCSP, in seed form as cryptogen keys are. Unless
// temporary, the BCCSP stores it in its keystore as <ski>_sk.
func importMLDSAPrivateKey(csp bccsp.BCCSP, sk *mldsa.PrivateKey, temporary bool) (bccsp.Key, error) {
	if _, ok := csp.(*pqc.CSP); !ok {
		return nil, errMLDSAKeyNeedsPQC
	}
	pub := sk.PublicKey()
	if pub.Parameters() != mldsa.MLDSA44() {
		return nil, errors.Errorf("unsupported ML-DSA parameter set %s: only ML-DSA-44 is supported", pub.Parameters())
	}
	seed := sk.Bytes()
	defer clear(seed)
	return csp.KeyImport(seed, &pqc.PrivateKeyImportOpts{AlgorithmName: pqc.MLDSA44, Temporary: temporary, PublicKey: pub.Bytes()})
}
