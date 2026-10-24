/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

func TestConfigureBCCSPPQCDefaultKeystore(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "client", "msp")

	// Client: <mspDir>/keystore, with no pqc section in the config.
	opts := &factory.FactoryOpts{Default: "PQC"}
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
	require.NotNil(t, opts.PQC)
	require.Equal(t, filepath.Join(mspDir, "keystore"), opts.PQC.KeyStorePath)

	// Server: msp/keystore under the home directory.
	opts = &factory.FactoryOpts{Default: "PQC", PQC: &factory.PQCOpts{}}
	require.NoError(t, ConfigureBCCSP(&opts, "", home))
	require.Equal(t, filepath.Join(home, "msp", "keystore"), opts.PQC.KeyStorePath)

	// Default is matched case-insensitively, as for SW.
	opts = &factory.FactoryOpts{Default: "pqc"}
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
	require.Equal(t, filepath.Join(mspDir, "keystore"), opts.PQC.KeyStorePath)
}

func TestConfigureBCCSPPQCKeepsConfiguredKeystore(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "client", "msp")
	explicit := filepath.Join(t.TempDir(), "pqc-keystore")

	// Client: the mspDir overrides a configured keystore path, as for SW.
	opts := &factory.FactoryOpts{Default: "PQC", PQC: &factory.PQCOpts{KeyStorePath: explicit}}
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
	require.Equal(t, filepath.Join(mspDir, "keystore"), opts.PQC.KeyStorePath, "the client's mspDir overrides a configured keystore path")

	// Server (and a client without an mspDir): a configured path is kept,
	// made absolute against the home directory if relative.
	opts = &factory.FactoryOpts{Default: "PQC", PQC: &factory.PQCOpts{KeyStorePath: explicit}}
	require.NoError(t, ConfigureBCCSP(&opts, "", home))
	require.Equal(t, explicit, opts.PQC.KeyStorePath, "an absolute keystore path is kept as given")

	opts = &factory.FactoryOpts{Default: "PQC", PQC: &factory.PQCOpts{KeyStorePath: "keys/pqc"}}
	require.NoError(t, ConfigureBCCSP(&opts, "", home))
	require.Equal(t, filepath.Join(home, "keys", "pqc"), opts.PQC.KeyStorePath, "a relative keystore path is made absolute against the home directory")
}

func TestConfigureBCCSPPQCRejectsPassword(t *testing.T) {
	opts := &factory.FactoryOpts{Default: "PQC", PQC: &factory.PQCOpts{Password: []byte("not-a-real-password")}}
	err := ConfigureBCCSP(&opts, t.TempDir(), t.TempDir())
	require.Error(t, err)
	require.Contains(t, err.Error(), "bccsp.pqc.password is not supported")
	require.NotContains(t, err.Error(), "not-a-real-password", "the error must not echo the password")
}

func TestConfigureBCCSPSWUnchanged(t *testing.T) {
	home := t.TempDir()
	mspDir := filepath.Join(home, "msp")

	// No default: SW with its usual defaults, and no PQC options created.
	var opts *factory.FactoryOpts
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
	require.Equal(t, "SW", opts.Default)
	require.Equal(t, "SHA2", opts.SW.Hash)
	require.Equal(t, 256, opts.SW.Security)
	require.Equal(t, filepath.Join(mspDir, "keystore"), opts.SW.FileKeystore.KeyStorePath)
	require.Nil(t, opts.PQC)

	// SW default with a leftover pqc section: the PQC options get no keystore.
	opts = &factory.FactoryOpts{Default: "SW", PQC: &factory.PQCOpts{}}
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
	require.Equal(t, filepath.Join(mspDir, "keystore"), opts.SW.FileKeystore.KeyStorePath)
	require.Empty(t, opts.PQC.KeyStorePath)

	// A password in a pqc section is only rejected when PQC is the default.
	opts = &factory.FactoryOpts{Default: "SW", PQC: &factory.PQCOpts{Password: []byte("x")}}
	require.NoError(t, ConfigureBCCSP(&opts, mspDir, home))
}
