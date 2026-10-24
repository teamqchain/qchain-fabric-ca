//go:build !pqc
// +build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"

	"github.com/cloudflare/cfssl/csr"
)

// generateMLDSACSR handles nothing without the pqc tag: there is no PQC
// BCCSP, so ML-DSA signers cannot occur, and every CSR goes through cfssl.
func generateMLDSACSR(crypto.Signer, *csr.CertificateRequest) ([]byte, bool, error) {
	return nil, false, nil
}
