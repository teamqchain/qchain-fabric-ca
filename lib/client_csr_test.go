/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

// testCSRInfo exercises every field cfssl's csr.Generate maps: all subject
// name parts, a serial number, and one host of each SAN kind.
func testCSRInfo() *api.CSRInfo {
	return &api.CSRInfo{
		Names: []csr.Name{
			{C: "AE", ST: "Sharjah", L: "Sharjah", O: "government.uae.com", OU: "client"},
			{OU: "issuers"},
		},
		Hosts:        []string{"peer0.government.uae.com", "10.0.0.7", "::1", "admin@government.uae.com", "spiffe://government.uae.com/issuer1"},
		SerialNumber: "SN-0001",
	}
}

func newTestClient(t *testing.T, csp *factory.FactoryOpts) *Client {
	t.Helper()
	c := &Client{HomeDir: t.TempDir(), Config: &ClientConfig{CSP: csp}}
	require.NoError(t, c.Init())
	return c
}

func parseCSRPEM(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, rest := pem.Decode(csrPEM)
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)
	req, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return req
}

// requireSameCSRFields checks that two CSRs carry identical subject, SANs and
// extensions (byte for byte, apart from the key and signature).
func requireSameCSRFields(t *testing.T, want, got *x509.CertificateRequest) {
	t.Helper()
	require.Equal(t, want.RawSubject, got.RawSubject, "subject")
	require.Equal(t, want.DNSNames, got.DNSNames)
	require.Equal(t, want.EmailAddresses, got.EmailAddresses)
	require.Equal(t, want.IPAddresses, got.IPAddresses)
	require.Equal(t, want.URIs, got.URIs)
	require.Equal(t, want.Extensions, got.Extensions, "extensions (SANs, basic constraints)")
}

// An ECDSA key still goes through cfssl's csr.Generate: the client's CSR is
// identical in subject, hosts and extensions to calling csr.Generate directly.
func TestClientGenCSRECDSAUnchanged(t *testing.T) {
	c := newTestClient(t, nil)
	csrPEM, key, err := c.GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)
	got := parseCSRPEM(t, csrPEM)
	require.NoError(t, got.CheckSignature())
	require.Equal(t, x509.ECDSAWithSHA256, got.SignatureAlgorithm)

	signer, err := cspsigner.New(c.csp, key)
	require.NoError(t, err)
	direct, err := csr.Generate(signer, c.newCertificateRequest(testCSRInfo(), "issuer1"))
	require.NoError(t, err)
	requireSameCSRFields(t, parseCSRPEM(t, direct), got)

	reused, _, err := c.GenCSRUsingKey(testCSRInfo(), "issuer1", key)
	require.NoError(t, err)
	requireSameCSRFields(t, parseCSRPEM(t, direct), parseCSRPEM(t, reused))
}
