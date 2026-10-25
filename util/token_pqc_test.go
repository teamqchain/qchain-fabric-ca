//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/mldsa"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// mldsaTokenIdentity returns a PQC BCCSP, an ML-DSA-44 key in it, and a
// self-signed certificate for the key.
func mldsaTokenIdentity(t *testing.T) (bccsp.BCCSP, bccsp.Key, []byte) {
	t.Helper()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, "", t.TempDir())
	require.NoError(t, err)
	key, signer, err := BCCSPKeyRequestGenerate(&csr.CertificateRequest{CN: "alice", KeyRequest: &csr.KeyRequest{A: "mldsa44"}}, csp)
	require.NoError(t, err)
	return csp, key, certPEM(mintCACert(t, signer).Raw)
}

// An ML-DSA token has the ECDSA token's format, and VerifyToken accepts it.
func TestCreateTokenMLDSA(t *testing.T) {
	csp, key, cert := mldsaTokenIdentity(t)
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
	require.NoError(t, mldsa.Verify(x509Cert.PublicKey.(*mldsa.PublicKey), digest[:], sig, nil),
		"the signature is ML-DSA over the SHA-256 digest of the payload")

	got, err := VerifyToken(csp, tok, "POST", "/register", body, false)
	require.NoError(t, err)
	require.Equal(t, x509Cert.Raw, got.Raw)

	// Two tokens in a row from the same key both verify.
	for i := 0; i < 2; i++ {
		tok, err := CreateToken(csp, cert, key, "GET", "/affiliations", nil)
		require.NoError(t, err)
		_, err = VerifyToken(csp, tok, "GET", "/affiliations", nil, false)
		require.NoError(t, err, "token %d", i+1)
	}

	// A classical server's BCCSP cannot check an ML-DSA token.
	_, err = VerifyToken(GetDefaultBCCSP(), tok, "POST", "/register", body, false)
	require.Error(t, err)
}

func TestVerifyTokenMLDSARejectsTampering(t *testing.T) {
	csp, key, cert := mldsaTokenIdentity(t)
	body := []byte("request body")
	tok, err := CreateToken(csp, cert, key, "POST", "/register", body)
	require.NoError(t, err)
	parts := strings.Split(tok, ".")

	_, err = VerifyToken(csp, tok, "POST", "/register", []byte("request bodY"), false)
	require.EqualError(t, err, "Token signature validation failed", "tampered body")

	sig, err := B64Decode(parts[1])
	require.NoError(t, err)
	sig[len(sig)/2] ^= 1
	_, err = VerifyToken(csp, parts[0]+"."+B64Encode(sig), "POST", "/register", body, false)
	require.EqualError(t, err, "Token signature validation failed", "tampered signature")

	// The signature with another ML-DSA certificate in its place.
	_, _, other := mldsaTokenIdentity(t)
	_, err = VerifyToken(csp, B64Encode(other)+"."+parts[1], "POST", "/register", body, false)
	require.EqualError(t, err, "Token signature validation failed", "token for a different certificate")
}
