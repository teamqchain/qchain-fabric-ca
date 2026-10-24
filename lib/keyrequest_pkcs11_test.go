//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkcs11"
	"github.com/stretchr/testify/require"
)

func TestGetKeyRequestPKCS11Unchanged(t *testing.T) {
	kr := GetKeyRequest(&CAConfig{CSP: &factory.FactoryOpts{Default: "PKCS11", PKCS11: &pkcs11.PKCS11Opts{Hash: "SHA2", Security: 384}}})
	require.Equal(t, &api.KeyRequest{Algo: "ecdsa", Size: 384}, kr)
}
