//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attrmgr"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func readCert(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(p)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// startPQCServer starts a CA with bccsp.default PQC, TLS off, and alice
// (role=issuer) and bob in its configured registry.
func startPQCServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	home := t.TempDir()
	port := freePort(t)
	srv := getServer(port, home, "", -1, t)
	require.NotNil(t, srv)
	srv.CA.Config.CSP = &factory.FactoryOpts{Default: "PQC"}
	srv.CA.Config.Registry.Identities = append(srv.CA.Config.Registry.Identities,
		CAConfigIdentity{Name: "alice", Pass: "alicepw", Type: "client", MaxEnrollments: -1, Attrs: map[string]string{"role": "issuer"}},
		CAConfigIdentity{Name: "bob", Pass: "bobpw", Type: "client", MaxEnrollments: -1},
	)
	require.NoError(t, srv.Start(), "a CA with bccsp.default PQC initializes and starts")
	t.Cleanup(func() { srv.Stop() })
	return srv, home, fmt.Sprintf("http://localhost:%d", port)
}

func pqcEnroll(t *testing.T, url, name, secret string, attrs []*api.AttributeRequest) *EnrollmentResponse {
	t.Helper()
	c := &Client{HomeDir: t.TempDir(), Config: &ClientConfig{URL: url, CSP: &factory.FactoryOpts{Default: "PQC"}}}
	resp, err := c.Enroll(&api.EnrollmentRequest{Name: name, Secret: secret, AttrReqs: attrs})
	require.NoError(t, err, "enroll %s", name)
	return resp
}

func TestPQCServerRootCAAndEnrollments(t *testing.T) {
	_, home, url := startPQCServer(t)

	// The CA's own root is ML-DSA-44, self-signed, and its key is in the PQC
	// keystore as <ski>_sk.
	rootPEM, err := os.ReadFile(filepath.Join(home, "ca-cert.pem"))
	require.NoError(t, err)
	root := readCert(t, rootPEM)
	require.Equal(t, x509.MLDSA44, root.SignatureAlgorithm)
	require.NoError(t, root.CheckSignatureFrom(root))
	require.True(t, root.IsCA)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, root.KeyUsage)
	keys, err := filepath.Glob(filepath.Join(home, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Len(t, keys, 1, "the CA key is stored as <ski>_sk")
	_, err = hex.DecodeString(filepath.Base(keys[0])[:64])
	require.NoError(t, err)

	// Enrollments in a row, each an ML-DSA-44 leaf signed by the root.
	for _, e := range []struct {
		name, secret string
		attrs        []*api.AttributeRequest
	}{
		{"admin", "adminpw", nil},
		{"admin", "adminpw", nil},
		{"alice", "alicepw", []*api.AttributeRequest{{Name: "role"}}},
		{"bob", "bobpw", nil},
	} {
		resp := pqcEnroll(t, url, e.name, e.secret, e.attrs)
		leaf := readCert(t, resp.Identity.GetECert().Cert())
		require.Equal(t, e.name, leaf.Subject.CommonName)
		require.IsType(t, &mldsa.PublicKey{}, leaf.PublicKey)
		require.Equal(t, x509.MLDSA44, leaf.SignatureAlgorithm)
		require.NoError(t, leaf.CheckSignatureFrom(root), "%s: leaf chains to the ML-DSA root", e.name)
		require.Equal(t, root.SubjectKeyId, leaf.AuthorityKeyId)

		if e.name == "alice" {
			attrs, err := attrmgr.New().GetAttributesFromCert(leaf)
			require.NoError(t, err)
			role, ok, err := attrs.Value("role")
			require.NoError(t, err)
			require.True(t, ok, "the role attribute extension (1.2.3.4.5.6.7.8.1) is present")
			require.Equal(t, "issuer", role)
		}
	}
}

// Registering through the API needs an authentication token from an
// ML-DSA identity, which util.CreateToken does not produce yet (F7).
func TestPQCServerRegisterBlockedUntilCreateToken(t *testing.T) {
	_, _, url := startPQCServer(t)
	admin := pqcEnroll(t, url, "admin", "adminpw", nil)
	_, err := admin.Identity.Register(&api.RegistrationRequest{Name: "carol", Type: "client", Affiliation: "", Attributes: []api.Attribute{{Name: "role", Value: "issuer", ECert: true}}})
	require.Error(t, err, "register works only once CreateToken handles ML-DSA (F7)")
	t.Logf("register as an ML-DSA identity today: %v", err)
}

// An ML-DSA CA refuses a classical CSR through the real enroll path (the
// F5b helper case, now against a real PQC server).
func TestPQCServerRefusesClassicalCSR(t *testing.T) {
	_, _, url := startPQCServer(t)
	cert, err := enrollAdmin(t, url, &api.KeyRequest{Algo: "ecdsa", Size: 256}, nil)
	require.Error(t, err)
	require.Nil(t, cert)
	require.Contains(t, err.Error(), "CSR public key algorithm ECDSA does not match the CA certificate's ML-DSA key: a CA only signs requests with the same key family (ML-DSA vs classical)")
}
