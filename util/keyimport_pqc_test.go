//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

// pqcCSP returns a PQC BCCSP and its keystore directory.
func pqcCSP(t *testing.T) (bccsp.BCCSP, string) {
	t.Helper()
	home := t.TempDir()
	opts := &factory.FactoryOpts{Default: "PQC"}
	csp, err := InitBCCSP(&opts, "", home)
	require.NoError(t, err)
	return csp, opts.PQC.KeyStorePath
}

// requireSignsLikePub signs three messages with key and checks each
// signature with stdlib crypto/mldsa against pub.
func requireSignsLikePub(t *testing.T, csp bccsp.BCCSP, key bccsp.Key, pub *mldsa.PublicKey) {
	t.Helper()
	for _, msg := range []string{"one", "two", "three"} {
		sig, err := csp.Sign(key, []byte(msg), nil)
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, []byte(msg), sig, nil), "signature on %q", msg)
	}
}

func keystoreFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A PKCS#8 ML-DSA-44 key minted with stdlib imports into the PQC BCCSP. A
// non-temporary import stores it as <ski>_sk; a temporary one stores nothing.
func TestImportMLDSAKeyIntoPQCBCCSP(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	keyFile := writeMLDSAKeyFile(t, sk)

	csp, ks := pqcCSP(t)
	key, err := ImportBCCSPKeyFromPEM(keyFile, csp, true)
	require.NoError(t, err)
	require.True(t, key.Private())
	require.Empty(t, keystoreFiles(t, ks), "a temporary import stores nothing")
	requireSignsLikePub(t, csp, key, sk.PublicKey())

	key, err = ImportBCCSPKeyFromPEM(keyFile, csp, false)
	require.NoError(t, err)
	require.Equal(t, []string{hex.EncodeToString(key.SKI()) + "_sk"}, keystoreFiles(t, ks))
	requireSignsLikePub(t, csp, key, sk.PublicKey())

	// The stored key is found again by its SKI.
	again, err := csp.GetKey(key.SKI())
	require.NoError(t, err)
	requireSignsLikePub(t, csp, again, sk.PublicKey())
}

// cryptogen's ML-DSA priv_sk imports and signs like its certificate's key.
// Set PQC_CRYPTOGEN to an ML-DSA capable cryptogen binary; it writes only
// to a temporary directory.
func TestImportCryptogenMLDSAKey(t *testing.T) {
	bin := os.Getenv("PQC_CRYPTOGEN")
	if bin == "" {
		t.Skip("PQC_CRYPTOGEN is not set to an ML-DSA capable cryptogen binary")
	}
	work := t.TempDir()
	config := filepath.Join(work, "crypto-config.yaml")
	require.NoError(t, os.WriteFile(config, []byte(`PeerOrgs:
  - Name: Org1
    Domain: org1.example.com
    CA:
      PublicKeyAlgorithm: mldsa44
    Template:
      Count: 1
      PublicKeyAlgorithm: mldsa44
    Users:
      Count: 1
      PublicKeyAlgorithm: mldsa44
`), 0o600))
	out := filepath.Join(work, "out")
	b, err := exec.Command(bin, "generate", "--config="+config, "--output="+out).CombinedOutput()
	require.NoError(t, err, "cryptogen: %s", b)

	dirs, err := filepath.Glob(filepath.Join(out, "peerOrganizations", "*", "users", "*", "msp"))
	require.NoError(t, err)
	ca, err := filepath.Glob(filepath.Join(out, "peerOrganizations", "*", "ca"))
	require.NoError(t, err)
	require.NotEmpty(t, dirs)
	require.Len(t, ca, 1)
	pairs := map[string][2]string{}
	for _, msp := range dirs {
		certs, err := filepath.Glob(filepath.Join(msp, "signcerts", "*.pem"))
		require.NoError(t, err)
		require.Len(t, certs, 1)
		pairs[filepath.Base(filepath.Dir(msp))] = [2]string{certs[0], filepath.Join(msp, "keystore", "priv_sk")}
	}
	caCerts, err := filepath.Glob(filepath.Join(ca[0], "*-cert.pem"))
	require.NoError(t, err)
	require.Len(t, caCerts, 1)
	pairs["ca"] = [2]string{caCerts[0], filepath.Join(ca[0], "priv_sk")}

	for name, p := range pairs {
		cert, err := GetX509CertificateFromPEMFile(p[0])
		require.NoError(t, err)
		pub, ok := cert.PublicKey.(*mldsa.PublicKey)
		require.True(t, ok, "%s: certificate key is %T", name, cert.PublicKey)
		csp, _ := pqcCSP(t)
		key, err := ImportBCCSPKeyFromPEM(p[1], csp, false)
		require.NoError(t, err, name)
		certKey, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
		require.NoError(t, err)
		require.Equal(t, certKey.SKI(), key.SKI(), "%s: the key's SKI is the certificate key's", name)
		requireSignsLikePub(t, csp, key, pub)
	}
}

// Bad key files fail with clear errors.
func TestImportMLDSAKeyBadInput(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	goodDER, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(sk.PublicKey())
	require.NoError(t, err)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, data, 0o600))
		return p
	}
	sk65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	csp, ks := pqcCSP(t)
	for _, c := range []struct {
		name, file, want string
	}{
		{"garbage", write("garbage", []byte("not a key")), "Failed parsing private key from " + filepath.Join(dir, "garbage") + ": Failed decoding PEM. Block must be different from nil."},
		{"garbage in a PEM block", write("garbage-pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})), "Failed parsing private key from " + filepath.Join(dir, "garbage-pem") + ": Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey"},
		// Truncated inside the PEM block, so that DER parsing fails.
		{"truncated key", write("truncated", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: goodDER[:len(goodDER)/2]})), "Failed parsing private key from " + filepath.Join(dir, "truncated") + ": Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey"},
		{"public key PEM", write("public", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), "Failed parsing private key from " + filepath.Join(dir, "public") + ": Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey"},
		{"ECDSA key", filepath.Join("testdata", "ec-key.pem"), "Failed to import ECDSA private key for 'testdata/ec-key.pem': unsupported PQC key-import algorithm \"ECDSA\""},
		{"ML-DSA-65 key", writeMLDSAKeyFile(t, sk65), "unsupported ML-DSA parameter set ML-DSA-65: only ML-DSA-44 is supported"},
	} {
		key, err := ImportBCCSPKeyFromPEM(c.file, csp, false)
		require.Error(t, err, c.name)
		require.Contains(t, err.Error(), c.want, c.name)
		require.Nil(t, key, c.name)
	}
	require.Empty(t, keystoreFiles(t, ks), "nothing was stored")
}
