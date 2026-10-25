/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// NewRootCAFromSigner returns a self-signed root CA certificate and its CSR,
// both PEM-encoded, as cfssl's initca.NewFromSigner does. initca cannot make
// the CSR for an ML-DSA signer, so for those the CSR comes from GenerateCSR
// and the certificate is signed by the same CA policy and cfssl local signer
// initca uses; crypto/x509 picks the ML-DSA signature algorithm from the key.
// Every other key type goes through initca.NewFromSigner unchanged.
func NewRootCAFromSigner(req *csr.CertificateRequest, priv crypto.Signer) (cert, csrPEM []byte, err error) {
	if !isMLDSAPublicKey(priv.Public()) {
		return initca.NewFromSigner(req, priv)
	}

	// As initca.NewFromSigner, with GenerateCSR in place of csr.Generate.
	policy := initca.CAPolicy()
	if req.CA != nil {
		if req.CA.Expiry != "" {
			policy.Default.ExpiryString = req.CA.Expiry
			policy.Default.Expiry, err = time.ParseDuration(req.CA.Expiry)
			if err != nil {
				return nil, nil, err
			}
		}

		policy.Default.CAConstraint.MaxPathLen = req.CA.PathLength
		if req.CA.PathLength != 0 && req.CA.PathLenZero {
			log.Infof("ignore invalid 'pathlenzero' value")
		} else {
			policy.Default.CAConstraint.MaxPathLenZero = req.CA.PathLenZero
		}
	}

	csrPEM, err = GenerateCSR(priv, req)
	if err != nil {
		return nil, nil, err
	}

	s, err := local.NewSigner(priv, nil, signer.DefaultSigAlgo(priv), policy)
	if err != nil {
		log.Errorf("failed to create signer: %v", err)
		return nil, nil, err
	}

	cert, err = s.Sign(signer.SignRequest{Request: string(csrPEM)})
	return cert, csrPEM, err
}
