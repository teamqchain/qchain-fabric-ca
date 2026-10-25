/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

// CheckCSRKeyFamily returns an error if the CSR's public key and the CA
// certificate's public key are not in the same key family: a CA with an
// ML-DSA key signs only ML-DSA requests, and a classical CA only classical
// ones. ML-DSA is detected in every build, since crypto/x509 parses ML-DSA
// CSRs even without the pqc tag.
func CheckCSRKeyFamily(csr *x509.CertificateRequest, caCert *x509.Certificate) error {
	if isMLDSAPublicKey(csr.PublicKey) == isMLDSAPublicKey(caCert.PublicKey) {
		return nil
	}
	return errors.Errorf("CSR public key algorithm %s does not match the CA certificate's %s key: a CA only signs requests with the same key family (ML-DSA vs classical)",
		csr.PublicKeyAlgorithm, caCert.PublicKeyAlgorithm)
}

// isMLDSAPublicKey reports whether pub is an ML-DSA public key.
func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}
