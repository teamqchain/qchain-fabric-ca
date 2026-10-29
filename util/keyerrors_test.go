/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireNoBytes fails if msg contains data, or its first 16 bytes, raw, in
// hex (as %x, %X or % x) or in base64. A failure never prints msg, which
// would hold the data.
func requireNoBytes(t *testing.T, msg string, data []byte) {
	t.Helper()
	for _, d := range [][]byte{data, data[:16]} {
		for name, enc := range map[string]string{
			"raw":           string(d),
			"hex":           hex.EncodeToString(d),
			"HEX":           strings.ToUpper(hex.EncodeToString(d)),
			"spaced hex":    fmt.Sprintf("% x", d),
			"base64":        base64.StdEncoding.EncodeToString(d),
			"raw base64":    base64.RawStdEncoding.EncodeToString(d),
			"base64 URL":    base64.URLEncoding.EncodeToString(d),
			"raw base64URL": base64.RawURLEncoding.EncodeToString(d),
		} {
			if strings.Contains(msg, enc) {
				t.Fatalf("the error contains the input (%s, %d bytes)", name, len(d))
			}
		}
	}
}

// Input that is not PEM is not echoed in the error, whatever it holds.
func TestPEMDecodeErrorsDoNotEchoInput(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, err)
	ml, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	mlDER, err := x509.MarshalPKCS8PrivateKey(ml)
	require.NoError(t, err)

	// requireErr checks err against want without printing err, which
	// could hold the data.
	requireErr := func(err error, want, what string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		if err.Error() != want {
			t.Fatalf("%s: the error is not %q (it is %d bytes long)", what, want, len(err.Error()))
		}
	}

	for name, data := range map[string][]byte{
		"ECDSA PKCS#8 DER":           ecDER,
		"ML-DSA PKCS#8 DER":          mlDER,
		"base64 key without headers": []byte(base64.StdEncoding.EncodeToString(ecDER)),
	} {
		_, err := PEMtoPrivateKey(data, nil)
		requireNoBytes(t, errString(err), data)
		requireErr(err, "Failed decoding PEM. Block must be different from nil.", name+": PEMtoPrivateKey")

		_, err = PEMtoAES(data, nil)
		requireNoBytes(t, errString(err), data)
		requireErr(err, "Failed decoding PEM. Block must be different from nil.", name+": PEMtoAES")

		_, err = PEMtoPublicKey(data, nil)
		requireNoBytes(t, errString(err), data)
		requireErr(err, "Failed decoding. Block must be different from nil.", name+": PEMtoPublicKey")

		keyFile := filepath.Join(t.TempDir(), "key.pem")
		require.NoError(t, os.WriteFile(keyFile, data, 0o600))
		_, err = ImportBCCSPKeyFromPEM(keyFile, GetDefaultBCCSP(), true)
		requireNoBytes(t, errString(err), data)
		requireErr(err, "Failed parsing private key from "+keyFile+": Failed decoding PEM. Block must be different from nil.", name+": ImportBCCSPKeyFromPEM")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
