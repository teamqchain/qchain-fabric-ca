/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"strings"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

// isPQCBCCSP reports whether bccsp.default is PQC.
func isPQCBCCSP(csp *factory.FactoryOpts) bool {
	return csp != nil && strings.ToUpper(csp.Default) == "PQC"
}

// pqcKeyRequest returns the key request used when none is given and
// bccsp.default is PQC, or nil for any other BCCSP.
func pqcKeyRequest(csp *factory.FactoryOpts) *api.KeyRequest {
	if isPQCBCCSP(csp) {
		return &api.KeyRequest{Algo: "mldsa44"}
	}
	return nil
}
