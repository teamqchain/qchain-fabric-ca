/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/require"
)

func startKeyFamilyServer(t *testing.T, caKey *api.KeyRequest) (*Server, string) {
	t.Helper()
	srv := startTestServer(t, func(port int) *Server {
		srv := getServer(port, t.TempDir(), "", -1, t)
		require.NotNil(t, srv)
		if caKey != nil {
			srv.CA.Config.CSR.KeyRequest = caKey
		}
		return srv
	})
	return srv, fmt.Sprintf("http://localhost:%d", srv.Config.Port)
}

func enrollAdmin(t *testing.T, url string, kr *api.KeyRequest, client *Client) (*x509.Certificate, error) {
	t.Helper()
	if client == nil {
		client = &Client{HomeDir: t.TempDir(), Config: &ClientConfig{URL: url}}
	}
	resp, err := client.Enroll(&api.EnrollmentRequest{Name: "admin", Secret: "adminpw", CSR: &api.CSRInfo{KeyRequest: kr}})
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(resp.Identity.GetECert().Cert())
	require.NotNil(t, block)
	return x509.ParseCertificate(block.Bytes)
}

// enrollRawCSR sends csrPEM to the real enroll endpoint as admin, the way
// Client.Enroll does after generating its CSR.
func enrollRawCSR(t *testing.T, url string, csrPEM []byte) error {
	t.Helper()
	c := &Client{HomeDir: t.TempDir(), Config: &ClientConfig{URL: url}}
	require.NoError(t, c.Init())
	reqNet := &api.EnrollmentRequestNet{}
	reqNet.SignRequest.Request = string(csrPEM)
	body, err := util.Marshal(reqNet, "SignRequest")
	require.NoError(t, err)
	post, err := c.newPost("enroll", body)
	require.NoError(t, err)
	post.SetBasicAuth("admin", "adminpw")
	return c.SendReq(post, &api.EnrollmentResponseNet{})
}

// A classical CA refuses an ML-DSA CSR in every build. Without the pqc tag
// the client cannot generate ML-DSA keys, so the CSR is built here with
// crypto/x509 and sent through the real enroll endpoint.
func TestClassicalCARefusesRawMLDSACSR(t *testing.T) {
	_, url := startKeyFamilyServer(t, nil)
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "admin"}}, sk)
	require.NoError(t, err)

	err = enrollRawCSR(t, url, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "CSR public key algorithm ML-DSA does not match the CA certificate's ECDSA key: a CA only signs requests with the same key family (ML-DSA vs classical)")
}

// Classical pairings are signed exactly as before, through the real enroll
// path.
func TestEnrollClassicalKeyFamiliesUnchanged(t *testing.T) {
	_, url := startKeyFamilyServer(t, nil) // ECDSA CA
	cert, err := enrollAdmin(t, url, &api.KeyRequest{Algo: "ecdsa", Size: 256}, nil)
	require.NoError(t, err, "ECDSA CA, ECDSA CSR")
	require.IsType(t, &ecdsa.PublicKey{}, cert.PublicKey)
	cert, err = enrollAdmin(t, url, &api.KeyRequest{Algo: "rsa", Size: 2048}, nil)
	require.NoError(t, err, "ECDSA CA, RSA CSR")
	require.IsType(t, &rsa.PublicKey{}, cert.PublicKey)

	_, url = startKeyFamilyServer(t, &api.KeyRequest{Algo: "rsa", Size: 2048}) // RSA CA
	cert, err = enrollAdmin(t, url, &api.KeyRequest{Algo: "ecdsa", Size: 256}, nil)
	require.NoError(t, err, "RSA CA, ECDSA CSR")
	require.IsType(t, &ecdsa.PublicKey{}, cert.PublicKey)
	require.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm, "signed by the RSA CA")
}
