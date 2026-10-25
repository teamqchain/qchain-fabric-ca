/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/stretchr/testify/require"
)

func rootCARequest(ca *csr.CAConfig) *csr.CertificateRequest {
	return &csr.CertificateRequest{
		CN:    "ca.government.uae.com",
		Names: []csr.Name{{C: "AE", ST: "Sharjah", L: "Sharjah", O: "government.uae.com", OU: "ca"}},
		Hosts: []string{"ca.government.uae.com", "127.0.0.1"},
		CA:    ca,
	}
}

func parseCertPEM(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(p)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func extensionIDs(cert *x509.Certificate) []string {
	var ids []string
	for _, e := range cert.Extensions {
		ids = append(ids, e.Id.String())
	}
	return ids
}

// requireSameRootFields compares everything initca sets on a root CA
// certificate, apart from the key, signature, serial number and timestamps.
func requireSameRootFields(t *testing.T, want, got *x509.Certificate) {
	t.Helper()
	require.Equal(t, want.RawSubject, got.RawSubject, "subject")
	require.Equal(t, want.RawIssuer, got.RawIssuer, "issuer")
	require.Equal(t, want.KeyUsage, got.KeyUsage)
	require.Equal(t, want.ExtKeyUsage, got.ExtKeyUsage)
	require.Equal(t, want.BasicConstraintsValid, got.BasicConstraintsValid)
	require.Equal(t, want.IsCA, got.IsCA)
	require.Equal(t, want.MaxPathLen, got.MaxPathLen)
	require.Equal(t, want.MaxPathLenZero, got.MaxPathLenZero)
	require.Equal(t, want.NotAfter.Sub(want.NotBefore), got.NotAfter.Sub(got.NotBefore), "validity period")
	require.Equal(t, want.DNSNames, got.DNSNames)
	require.Equal(t, want.IPAddresses, got.IPAddresses)
	require.Equal(t, want.AuthorityKeyId, got.AuthorityKeyId)
	require.Equal(t, extensionIDs(want), extensionIDs(got), "extensions")
}

// A classical key still goes through initca.NewFromSigner: same fields as
// calling initca directly.
func TestNewRootCAFromSignerECDSAUnchanged(t *testing.T) {
	key := ecdsaTestKey(t)
	req := rootCARequest(&csr.CAConfig{Expiry: "131400h", PathLength: 1})

	certPEM, csrPEM, err := NewRootCAFromSigner(req, key)
	require.NoError(t, err)
	got := parseCertPEM(t, certPEM)
	require.Equal(t, x509.ECDSAWithSHA256, got.SignatureAlgorithm)
	require.NoError(t, got.CheckSignatureFrom(got))
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)

	wantPEM, _, err := initca.NewFromSigner(req, key)
	require.NoError(t, err)
	requireSameRootFields(t, parseCertPEM(t, wantPEM), got)
}
