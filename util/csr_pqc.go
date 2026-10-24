//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/mail"
	"net/url"

	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
)

// generateMLDSACSR builds the CSR for an ML-DSA signer the way cfssl's
// csr.Generate does for RSA and ECDSA: same subject, host SANs and CA
// basic constraints, PEM type CERTIFICATE REQUEST. crypto/x509 chooses the
// ML-DSA signature algorithm from the key. It reports handled=false for any
// other key type.
func generateMLDSACSR(priv crypto.Signer, req *csr.CertificateRequest) (csrPEM []byte, handled bool, err error) {
	if _, ok := priv.Public().(*mldsa.PublicKey); !ok {
		return nil, false, nil
	}

	tpl := x509.CertificateRequest{Subject: req.Name()}
	for _, host := range req.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(host); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else if uri, err := url.ParseRequestURI(host); err == nil && uri != nil {
			tpl.URIs = append(tpl.URIs, uri)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, host)
		}
	}
	if req.CA != nil {
		// As cfssl's unexported appendCAInfoToCSR.
		pathlen := req.CA.PathLength
		if pathlen == 0 && !req.CA.PathLenZero {
			pathlen = -1
		}
		val, err := asn1.Marshal(csr.BasicConstraints{IsCA: true, MaxPathLen: pathlen})
		if err != nil {
			return nil, true, cferr.Wrap(cferr.CSRError, cferr.GenerationFailed, err)
		}
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: val, Critical: true}}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		log.Errorf("failed to generate a CSR: %v", err)
		return nil, true, cferr.Wrap(cferr.CSRError, cferr.BadRequest, err)
	}
	log.Info("encoded CSR")
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), true, nil
}
