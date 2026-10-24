/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/stretchr/testify/require"
)

func TestGetBCCSPKeyOptsClassicalUnchanged(t *testing.T) {
	opts, err := getBCCSPKeyOpts(nil, false)
	require.NoError(t, err)
	require.IsType(t, &bccsp.ECDSAKeyGenOpts{}, opts, "no key request still means ECDSA")

	for _, c := range []struct {
		kr   *csr.KeyRequest
		want bccsp.KeyGenOpts
	}{
		{&csr.KeyRequest{A: "ecdsa", S: 256}, &bccsp.ECDSAP256KeyGenOpts{}},
		{&csr.KeyRequest{A: "ecdsa", S: 384}, &bccsp.ECDSAP384KeyGenOpts{}},
		{&csr.KeyRequest{A: "rsa", S: 2048}, &bccsp.RSA2048KeyGenOpts{}},
		{&csr.KeyRequest{A: "rsa", S: 4096}, &bccsp.RSA4096KeyGenOpts{}},
	} {
		opts, err := getBCCSPKeyOpts(c.kr, true)
		require.NoError(t, err)
		require.IsType(t, c.want, opts)
		require.True(t, opts.Ephemeral())
	}

	for _, c := range []struct {
		kr      *csr.KeyRequest
		wantErr string
	}{
		{&csr.KeyRequest{A: "ecdsa", S: 521}, "Unsupported ECDSA key size: 521"},
		{&csr.KeyRequest{A: "ecdsa", S: 123}, "Invalid ECDSA key size: 123"},
		{&csr.KeyRequest{A: "rsa", S: 1024}, "Invalid RSA key size: 1024"},
		{&csr.KeyRequest{A: "foo", S: 256}, "Invalid algorithm: foo"},
		{&csr.KeyRequest{A: "MLDSA44"}, "Invalid algorithm: MLDSA44"},
	} {
		_, err := getBCCSPKeyOpts(c.kr, false)
		require.EqualError(t, err, c.wantErr)
	}
}

func TestGetBCCSPKeyOptsMLDSA44RejectsSize(t *testing.T) {
	_, err := getBCCSPKeyOpts(&csr.KeyRequest{A: "mldsa44", S: 256}, false)
	require.EqualError(t, err, "Invalid mldsa44 key size: 256 (omit the size or set it to 0)")
}
