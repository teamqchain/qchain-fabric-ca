/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attrmgr"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// tokenFlow drives the token-authenticated requests against srv, a CA with
// only its bootstrap admin, with clients using csp: the admin registers
// alice (role=issuer) and bob, both enroll, alice reenrolls herself, the
// admin revokes bob and generates a CRL. Every certificate must chain to
// the CA's root and have a public key of type keyType.
func tokenFlow(t *testing.T, srv *Server, csp *factory.FactoryOpts, keyType string) {
	url := fmt.Sprintf("http://localhost:%d", srv.Config.Port)
	rootPEM, err := os.ReadFile(filepath.Join(srv.HomeDir, "ca-cert.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(rootPEM)
	require.NotNil(t, block)
	root, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	enroll := func(name, secret string) *Identity {
		c := &Client{HomeDir: t.TempDir(), Config: &ClientConfig{URL: url, CSP: csp}}
		resp, err := c.Enroll(&api.EnrollmentRequest{Name: name, Secret: secret})
		require.NoError(t, err, "enroll %s", name)
		return resp.Identity
	}
	leaf := func(name string, id *Identity) *x509.Certificate {
		cert := id.GetECert().GetX509Cert()
		require.Equal(t, name, cert.Subject.CommonName)
		require.Equal(t, keyType, fmt.Sprintf("%T", cert.PublicKey), "%s's key", name)
		require.NoError(t, cert.CheckSignatureFrom(root), "%s's certificate chains to the root", name)
		return cert
	}
	role := func(cert *x509.Certificate) string {
		attrs, err := attrmgr.New().GetAttributesFromCert(cert)
		require.NoError(t, err)
		v, _, err := attrs.Value("role")
		require.NoError(t, err)
		return v
	}

	admin := enroll("admin", "adminpw")
	leaf("admin", admin)
	for _, r := range []*api.RegistrationRequest{
		{Name: "alice", Secret: "alicepw", Type: "client", Attributes: []api.Attribute{{Name: "role", Value: "issuer", ECert: true}}},
		{Name: "bob", Secret: "bobpw", Type: "client"},
	} {
		_, err := admin.Register(r)
		require.NoError(t, err, "the admin registers %s", r.Name)
	}
	alice := enroll("alice", "alicepw")
	aliceCert := leaf("alice", alice)
	require.Equal(t, "issuer", role(aliceCert))
	bob := enroll("bob", "bobpw")
	bobCert := leaf("bob", bob)

	// alice reenrolls herself.
	re, err := alice.Reenroll(&api.ReenrollmentRequest{})
	require.NoError(t, err, "alice reenrolls")
	reCert := leaf("alice", re.Identity)
	require.NotEqual(t, aliceCert.SerialNumber, reCert.SerialNumber)
	require.Equal(t, "issuer", role(reCert))

	// The admin cannot reenroll alice's certificate: a token that carries it
	// but is signed with the admin's key fails the signature check, which
	// the client sees as an authentication (not authorization) failure.
	body, err := util.Marshal(api.ReenrollmentRequest{}, "ReenrollmentRequest")
	require.NoError(t, err)
	req, err := admin.client.newPost("reenroll", body)
	require.NoError(t, err)
	tok, err := util.CreateToken(admin.client.csp, alice.GetECert().Cert(), admin.GetECert().Key(), req.Method, req.URL.RequestURI(), body)
	require.NoError(t, err)
	req.Header.Set("authorization", tok)
	err = admin.client.SendReq(req, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Error Code: 20 - Authentication failure")
	_, err = util.VerifyToken(srv.CA.csp, tok, req.Method, req.URL.RequestURI(), body, false)
	require.EqualError(t, err, "Token signature validation failed", "the CA's own check rejects the signature")

	// The admin revokes bob by enrollment ID and generates a CRL that the
	// root signed and that lists bob's certificate.
	rr, err := admin.Revoke(&api.RevocationRequest{Name: "bob"})
	require.NoError(t, err, "the admin revokes bob")
	require.Len(t, rr.RevokedCerts, 1)
	serial, ok := new(big.Int).SetString(rr.RevokedCerts[0].Serial, 16)
	require.True(t, ok)
	require.Equal(t, 0, serial.Cmp(bobCert.SerialNumber))

	gen, err := admin.GenCRL(&api.GenCRLRequest{})
	require.NoError(t, err, "the admin generates a CRL")
	block, _ = pem.Decode(gen.CRL)
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, root.SignatureAlgorithm, crl.SignatureAlgorithm)
	require.NoError(t, crl.CheckSignatureFrom(root), "the root signed the CRL")
	var listed []*big.Int
	for _, e := range crl.RevokedCertificateEntries {
		listed = append(listed, e.SerialNumber)
	}
	require.Len(t, listed, 1)
	require.Equal(t, 0, listed[0].Cmp(bobCert.SerialNumber), "bob's serial is listed")

	// bob's token is refused once he is revoked.
	_, err = bob.Reenroll(&api.ReenrollmentRequest{})
	require.Error(t, err)
}

// The token flow on a classical CA with ECDSA identities, in every build.
func TestTokenFlowClassical(t *testing.T) {
	srv, _ := startKeyFamilyServer(t, nil)
	tokenFlow(t, srv, nil, "*ecdsa.PublicKey")
}
