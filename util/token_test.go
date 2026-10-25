/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// tokenPayload is what a token for method, uri, body and cert signs.
func tokenPayload(method, uri string, body, cert []byte) []byte {
	return []byte(method + "." + B64Encode([]byte(uri)) + "." + B64Encode(body) + "." + B64Encode(cert))
}

// An ECDSA token keeps its format: <b64 cert>.<b64 ASN.1 ECDSA signature
// over the SHA-256 digest of the payload>.
func TestCreateTokenECDSAFormat(t *testing.T) {
	csp := GetDefaultBCCSP()
	key, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), csp, true)
	require.NoError(t, err)
	cert, err := os.ReadFile(filepath.Join("testdata", "ec.pem"))
	require.NoError(t, err)
	body := []byte("request body")

	tok, err := CreateToken(csp, cert, key, "POST", "/register", body)
	require.NoError(t, err)
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 2)
	require.Equal(t, B64Encode(cert), parts[0])
	sig, err := B64Decode(parts[1])
	require.NoError(t, err)
	x509Cert, err := GetX509CertificateFromPEM(cert)
	require.NoError(t, err)
	digest := sha256.Sum256(tokenPayload("POST", "/register", body, cert))
	require.True(t, ecdsa.VerifyASN1(x509Cert.PublicKey.(*ecdsa.PublicKey), digest[:], sig))

	_, err = VerifyToken(csp, tok, "POST", "/register", body, false)
	require.NoError(t, err)
}

// CreateToken refuses key types it has no token for, instead of returning
// an empty token.
func TestCreateTokenUnsupportedKeyTypes(t *testing.T) {
	csp := GetDefaultBCCSP()
	key, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), csp, true)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for alg, signer := range map[string]crypto.Signer{"Ed25519": edKey, "RSA": rsaTestKey(t)} {
		cert := certPEM(mintCACert(t, signer).Raw)
		tok, err := CreateToken(csp, cert, key, "POST", "/register", []byte("body"))
		require.EqualError(t, err, "token authentication is not supported for "+alg+" keys")
		require.Empty(t, tok)
	}
}

// A missing certificate is an error, not an empty token.
func TestCreateTokenNoCertificate(t *testing.T) {
	csp := GetDefaultBCCSP()
	key, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), csp, true)
	require.NoError(t, err)
	for _, cert := range [][]byte{nil, {}} {
		tok, err := CreateToken(csp, cert, key, "POST", "/register", []byte("body"))
		require.EqualError(t, err, "Failed to PEM decode certificate")
		require.Empty(t, tok)
	}
}
