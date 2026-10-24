/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"

	"github.com/cloudflare/cfssl/csr"
)

// GenerateCSR returns a PEM-encoded CSR for req, signed by priv. cfssl's
// csr.Generate does not support ML-DSA signers; in builds with the pqc tag
// they get an equivalent CSR built with crypto/x509. Every other key type
// goes through csr.Generate unchanged.
func GenerateCSR(priv crypto.Signer, req *csr.CertificateRequest) ([]byte, error) {
	if csrPEM, handled, err := generateMLDSACSR(priv, req); handled {
		return csrPEM, err
	}
	return csr.Generate(priv, req)
}
