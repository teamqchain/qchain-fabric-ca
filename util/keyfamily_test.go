/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mintCACert returns a self-signed CA certificate for key.
func mintCACert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// mintCSR returns a CSR signed by key.
func mintCSR(t *testing.T, key crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

func ecdsaTestKey(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func rsaTestKey(t *testing.T) crypto.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func mldsaTestKey(t *testing.T) crypto.Signer {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	return k
}

// ML-DSA is detected in every build, with or without the pqc tag.
func TestCheckCSRKeyFamilyMLDSA(t *testing.T) {
	require.NoError(t, CheckCSRKeyFamily(mintCSR(t, mldsaTestKey(t)), mintCACert(t, mldsaTestKey(t))), "ML-DSA CA, ML-DSA CSR")

	for name, c := range map[string]struct {
		ca, csr crypto.Signer
		wantErr string
	}{
		"ML-DSA CA, ECDSA CSR": {mldsaTestKey(t), ecdsaTestKey(t),
			"CSR public key algorithm ECDSA does not match the CA certificate's ML-DSA key: a CA only signs requests with the same key family (ML-DSA vs classical)"},
		"ML-DSA CA, RSA CSR": {mldsaTestKey(t), rsaTestKey(t),
			"CSR public key algorithm RSA does not match the CA certificate's ML-DSA key: a CA only signs requests with the same key family (ML-DSA vs classical)"},
		"ECDSA CA, ML-DSA CSR": {ecdsaTestKey(t), mldsaTestKey(t),
			"CSR public key algorithm ML-DSA does not match the CA certificate's ECDSA key: a CA only signs requests with the same key family (ML-DSA vs classical)"},
		"RSA CA, ML-DSA CSR": {rsaTestKey(t), mldsaTestKey(t),
			"CSR public key algorithm ML-DSA does not match the CA certificate's RSA key: a CA only signs requests with the same key family (ML-DSA vs classical)"},
	} {
		require.EqualError(t, CheckCSRKeyFamily(mintCSR(t, c.csr), mintCACert(t, c.ca)), c.wantErr, name)
	}
}

// Classical pairings are accepted, in every build.
func TestCheckCSRKeyFamilyClassical(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for name, c := range map[string]struct{ ca, csr crypto.Signer }{
		"ECDSA CA, ECDSA CSR":   {ecdsaTestKey(t), ecdsaTestKey(t)},
		"ECDSA CA, RSA CSR":     {ecdsaTestKey(t), rsaTestKey(t)},
		"RSA CA, ECDSA CSR":     {rsaTestKey(t), ecdsaTestKey(t)},
		"Ed25519 CA, ECDSA CSR": {ed, ecdsaTestKey(t)},
	} {
		require.NoError(t, CheckCSRKeyFamily(mintCSR(t, c.csr), mintCACert(t, c.ca)), name)
	}
}
