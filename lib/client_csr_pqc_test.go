//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func pqcTestClient(t *testing.T) *Client {
	return newTestClient(t, &factory.FactoryOpts{Default: "PQC"})
}

func TestClientGenCSRMLDSA44(t *testing.T) {
	c := pqcTestClient(t)
	csrPEM, key, err := c.GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)
	req := parseCSRPEM(t, csrPEM) // PEM type CERTIFICATE REQUEST, parses with crypto/x509
	require.NoError(t, req.CheckSignature())
	require.Equal(t, x509.MLDSA44, req.SignatureAlgorithm)
	require.Equal(t, x509.MLDSA, req.PublicKeyAlgorithm)

	pub, ok := req.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok, "CSR public key is %T", req.PublicKey)
	require.Equal(t, mldsa.MLDSA44(), pub.Parameters())
	k, err := key.PublicKey()
	require.NoError(t, err)
	want, err := k.Bytes()
	require.NoError(t, err)
	got, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	require.Equal(t, want, got, "the CSR carries the generated key")

	s := req.Subject
	require.Equal(t, "issuer1", s.CommonName)
	require.Equal(t, []string{"AE"}, s.Country)
	require.Equal(t, []string{"Sharjah"}, s.Province)
	require.Equal(t, []string{"Sharjah"}, s.Locality)
	require.Equal(t, []string{"government.uae.com"}, s.Organization)
	require.Equal(t, []string{"client", "issuers"}, s.OrganizationalUnit)
	require.Equal(t, "SN-0001", s.SerialNumber)
	require.Equal(t, []string{"peer0.government.uae.com"}, req.DNSNames)
	require.Equal(t, []string{"admin@government.uae.com"}, req.EmailAddresses)
	require.Len(t, req.IPAddresses, 2)
	require.True(t, req.IPAddresses[0].Equal(net.ParseIP("10.0.0.7")))
	require.True(t, req.IPAddresses[1].Equal(net.ParseIP("::1")))
	require.Len(t, req.URIs, 1)
	require.Equal(t, "spiffe://government.uae.com/issuer1", req.URIs[0].String())
}

// The ML-DSA CSR carries the same subject, SANs and extensions as cfssl's
// csr.Generate produces for an ECDSA key from the same request.
func TestClientMLDSACSRFieldParityWithCfssl(t *testing.T) {
	ecdsaClient := newTestClient(t, nil)
	pqcClient := pqcTestClient(t)
	for name, mod := range map[string]func(*csr.CAConfig){
		"no CA request":    nil,
		"CA, no pathlen":   func(*csr.CAConfig) {},
		"CA, pathlen 2":    func(ca *csr.CAConfig) { ca.PathLength = 2 },
		"CA, pathlen zero": func(ca *csr.CAConfig) { ca.PathLenZero = true },
	} {
		info := testCSRInfo()
		if mod != nil {
			info.CA = &csr.CAConfig{}
			mod(info.CA)
		}
		classical, _, err := ecdsaClient.GenCSR(info, "issuer1")
		require.NoError(t, err, name)
		mldsaCSR, _, err := pqcClient.GenCSR(info, "issuer1")
		require.NoError(t, err, name)
		want, got := parseCSRPEM(t, classical), parseCSRPEM(t, mldsaCSR)
		require.Equal(t, x509.ECDSAWithSHA256, want.SignatureAlgorithm, name)
		require.Equal(t, x509.MLDSA44, got.SignatureAlgorithm, name)
		requireSameCSRFields(t, want, got)
		if mod != nil {
			require.Len(t, got.Extensions, 2, "%s: SAN and basic constraints", name)
		}
	}
}

// The parse steps of processSignRequest (lib/serverenroll.go) and cfssl's
// signature-checking CSR parse accept the ML-DSA CSR.
func TestMLDSACSRAcceptedByServerParse(t *testing.T) {
	csrPEM, _, err := pqcTestClient(t).GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)

	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	require.True(t, block.Type == "NEW CERTIFICATE REQUEST" || block.Type == "CERTIFICATE REQUEST")
	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, "issuer1", csrReq.Subject.CommonName)
	require.NoError(t, csrInputLengthCheck(csrReq))

	parsed, _, err := helpers.ParseCSR(csrPEM)
	require.NoError(t, err)
	require.NoError(t, parsed.CheckSignature())
}

// CSRs from two different keys both verify, and a reused key signs again:
// guards against a key that signs only once.
func TestMLDSACSRTwoKeysBothVerify(t *testing.T) {
	c := pqcTestClient(t)
	csr1, key1, err := c.GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)
	csr2, key2, err := c.GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)
	require.NotEqual(t, key1.SKI(), key2.SKI(), "two different keys")
	again, _, err := c.GenCSRUsingKey(testCSRInfo(), "issuer1", key1)
	require.NoError(t, err)

	for i, p := range [][]byte{csr1, csr2, again} {
		require.NoError(t, parseCSRPEM(t, p).CheckSignature(), "CSR %d", i+1)
	}
	require.Equal(t, parseCSRPEM(t, csr1).RawSubjectPublicKeyInfo, parseCSRPEM(t, again).RawSubjectPublicKeyInfo, "GenCSRUsingKey reuses the key")
}

func TestMLDSACSRTamperedBodyFailsCheckSignature(t *testing.T) {
	csrPEM, _, err := pqcTestClient(t).GenCSR(testCSRInfo(), "issuer1")
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)

	der := append([]byte(nil), block.Bytes...)
	i := bytes.Index(der, []byte("issuer1"))
	require.GreaterOrEqual(t, i, 0)
	der[i+len("issuer")] = '2' // CN issuer1 -> issuer2, inside the signed body
	tampered, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.Equal(t, "issuer2", tampered.Subject.CommonName)
	require.Error(t, tampered.CheckSignature())
}
