/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func clientWithBCCSP(csp *factory.FactoryOpts) *Client {
	return &Client{Config: &ClientConfig{CSP: csp}}
}

// Requests with no key request: nil CSR info, CSR info without a key
// request, and an empty key request.
var noKeyRequest = []*api.CSRInfo{nil, {}, {KeyRequest: &api.KeyRequest{}}}

func TestClientDefaultKeyRequestFollowsPQCDefault(t *testing.T) {
	for _, def := range []string{"PQC", "pqc"} {
		c := clientWithBCCSP(&factory.FactoryOpts{Default: def, SW: &factory.SwOpts{Security: 256, Hash: "SHA2"}})
		for i, req := range noKeyRequest {
			cr := c.newCertificateRequest(req, "alice")
			require.Equal(t, &csr.KeyRequest{A: "mldsa44"}, cr.KeyRequest, "bccsp.default %q, request %d", def, i)
		}
	}
}

func TestClientExplicitKeyRequestWins(t *testing.T) {
	for _, c := range []struct {
		def  string
		kr   *api.KeyRequest
		want *csr.KeyRequest
	}{
		{"PQC", &api.KeyRequest{Algo: "ecdsa", Size: 256}, &csr.KeyRequest{A: "ecdsa", S: 256}},
		{"PQC", &api.KeyRequest{Algo: "mldsa44"}, &csr.KeyRequest{A: "mldsa44"}},
		{"SW", &api.KeyRequest{Algo: "mldsa44"}, &csr.KeyRequest{A: "mldsa44"}},
		{"SW", &api.KeyRequest{Algo: "ecdsa", Size: 384}, &csr.KeyRequest{A: "ecdsa", S: 384}},
	} {
		cr := clientWithBCCSP(&factory.FactoryOpts{Default: c.def}).newCertificateRequest(&api.CSRInfo{KeyRequest: c.kr}, "alice")
		require.Equal(t, c.want, cr.KeyRequest, "bccsp.default %q, explicit %+v", c.def, *c.kr)
	}
}

func TestClientDefaultKeyRequestClassicalUnchanged(t *testing.T) {
	ecdsaP256 := &csr.KeyRequest{A: "ecdsa", S: 256}
	for name, c := range map[string]*Client{
		"SW default":       clientWithBCCSP(&factory.FactoryOpts{Default: "SW", SW: &factory.SwOpts{Security: 256, Hash: "SHA2"}}),
		"SW security 384":  clientWithBCCSP(&factory.FactoryOpts{Default: "SW", SW: &factory.SwOpts{Security: 384, Hash: "SHA2"}}),
		"no bccsp block":   clientWithBCCSP(nil),
		"no client config": {},
	} {
		for i, req := range noKeyRequest {
			cr := c.newCertificateRequest(req, "alice")
			require.Equal(t, ecdsaP256, cr.KeyRequest, "%s, request %d", name, i)
		}
	}

	// With no CSR info the requested hosts are still the local hostname.
	if hostname, _ := os.Hostname(); hostname != "" {
		cr := clientWithBCCSP(&factory.FactoryOpts{Default: "PQC"}).newCertificateRequest(nil, "alice")
		require.Equal(t, []string{hostname}, cr.Hosts)
	}
}
