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
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	cfsigner "github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// bccspMLDSASigner returns a BCCSP-backed ML-DSA-44 signer, as the CA gets
// for its own key.
func bccspMLDSASigner(t *testing.T) crypto.Signer {
	t.Helper()
	home := t.TempDir()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, "", home)
	require.NoError(t, err)
	_, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "ca", KeyRequest: &csr.KeyRequest{A: "mldsa44"}}, csp)
	require.NoError(t, err)
	return signer
}

func TestNewRootCAFromSignerMLDSA44(t *testing.T) {
	signer := bccspMLDSASigner(t)
	certPEM, csrPEM, err := NewRootCAFromSigner(rootCARequest(&csr.CAConfig{Expiry: "131400h", PathLength: 1}), signer)
	require.NoError(t, err)

	root := parseCertPEM(t, certPEM)
	require.Equal(t, x509.MLDSA44, root.SignatureAlgorithm)
	require.Equal(t, x509.MLDSA, root.PublicKeyAlgorithm)
	require.NoError(t, root.CheckSignatureFrom(root), "the root verifies itself")
	require.True(t, root.IsCA)
	require.True(t, root.BasicConstraintsValid)
	require.Equal(t, 1, root.MaxPathLen)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, root.KeyUsage)
	require.Equal(t, "ca.government.uae.com", root.Subject.CommonName)
	require.Equal(t, []string{"government.uae.com"}, root.Subject.Organization)
	require.Equal(t, []string{"AE"}, root.Subject.Country)
	require.Equal(t, root.RawSubject, root.RawIssuer, "self-signed")
	require.Equal(t, 131400*time.Hour, root.NotAfter.Sub(root.NotBefore), "expiry from the CA config")
	require.Empty(t, root.DNSNames, "hosts are not kept on a CA certificate, as with initca")

	pub, ok := root.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok)
	require.True(t, pub.Equal(signer.Public()), "the root carries the CA key")
	ski, err := cfsigner.ComputeSKI(&x509.Certificate{PublicKey: pub})
	require.NoError(t, err)
	require.Equal(t, ski, root.SubjectKeyId, "SKI as cfssl computes it for every fabric-ca certificate")

	csrReq := parseCSRPEMForTest(t, csrPEM)
	require.NoError(t, csrReq.CheckSignature())
	require.Equal(t, x509.MLDSA44, csrReq.SignatureAlgorithm)
	require.Equal(t, root.RawSubject, csrReq.RawSubject)

	zero, _, err := NewRootCAFromSigner(rootCARequest(&csr.CAConfig{PathLenZero: true}), signer)
	require.NoError(t, err)
	z := parseCertPEM(t, zero)
	require.Equal(t, 0, z.MaxPathLen)
	require.True(t, z.MaxPathLenZero)
	require.Equal(t, 43800*time.Hour, z.NotAfter.Sub(z.NotBefore), "initca's default expiry when none is configured")
}

// The ML-DSA root has the same fields initca gives an ECDSA root for the
// same request.
func TestNewRootCAFromSignerMLDSAFieldParityWithInitca(t *testing.T) {
	for name, ca := range map[string]*csr.CAConfig{
		"expiry and pathlen": {Expiry: "131400h", PathLength: 2},
		"pathlen zero":       {PathLenZero: true},
		"no CA config":       nil,
	} {
		req := rootCARequest(ca)
		mldsaPEM, _, err := NewRootCAFromSigner(req, bccspMLDSASigner(t))
		require.NoError(t, err, name)
		ecdsaPEM, _, err := initca.NewFromSigner(req, ecdsaTestKey(t))
		require.NoError(t, err, name)
		requireSameRootFields(t, parseCertPEM(t, ecdsaPEM), parseCertPEM(t, mldsaPEM))
	}
}

// Roots from two different keys both verify, and one key makes two roots.
func TestNewRootCAFromSignerTwoKeys(t *testing.T) {
	s1, s2 := bccspMLDSASigner(t), bccspMLDSASigner(t)
	for i, s := range []crypto.Signer{s1, s2, s1} {
		certPEM, _, err := NewRootCAFromSigner(rootCARequest(nil), s)
		require.NoError(t, err, "root %d", i+1)
		root := parseCertPEM(t, certPEM)
		require.NoError(t, root.CheckSignatureFrom(root), "root %d", i+1)
	}
	require.False(t, s1.Public().(*mldsa.PublicKey).Equal(s2.Public()))
}

func parseCSRPEMForTest(t *testing.T, p []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(p)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)
	req, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return req
}
