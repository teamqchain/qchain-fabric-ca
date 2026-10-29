/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// testPQCPassword stands in for a password; failures never print errors
// that could contain it.
const testPQCPassword = "dummy-pqc-pw-7f3a"

const pqcPasswordRefusal = "bccsp.pqc.password is not supported: the PQC BCCSP stores ML-DSA private keys unencrypted; remove the password"

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0o600))
	return f
}

// requireRefusal checks err without printing it.
func requireRefusal(t *testing.T, err error, file, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the configuration loaded", what)
	}
	if strings.Contains(err.Error(), testPQCPassword) {
		t.Fatalf("%s: the error contains the password", what)
	}
	if want := "Invalid configuration in file '" + file + "': " + pqcPasswordRefusal; err.Error() != want {
		t.Fatalf("%s: the error is not %q (it is %d bytes long)", what, want, len(err.Error()))
	}
}

// A bccsp.pqc.password in a server or CA configuration file is refused
// before decoding, in every build, without showing the password.
func TestUnmarshalConfigRefusesPQCPassword(t *testing.T) {
	for name, yaml := range map[string]string{
		"lower case": "bccsp:\n  default: PQC\n  pqc:\n    keystorepath: msp/keystore\n    password: " + testPQCPassword + "\n",
		"upper case": "BCCSP:\n  Default: PQC\n  PQC:\n    Password: " + testPQCPassword + "\n",
		"SW default": "bccsp:\n  default: SW\n  pqc:\n    password: " + testPQCPassword + "\n",
	} {
		f := writeConfig(t, yaml)
		requireRefusal(t, UnmarshalConfig(&ServerConfig{}, viper.New(), f, true), f, name+": server")
		requireRefusal(t, UnmarshalConfig(&CAConfig{}, viper.New(), f, false), f, name+": CA file")
	}
}

// A PQC section without a password, or with an empty one, still loads.
func TestUnmarshalConfigPQCWithoutPassword(t *testing.T) {
	for name, yaml := range map[string]string{
		"no password":    "bccsp:\n  default: PQC\n  pqc:\n    keystorepath: msp/keystore\n",
		"empty password": "bccsp:\n  default: PQC\n  pqc:\n    keystorepath: msp/keystore\n    password: \"\"\n",
	} {
		cfg := &ServerConfig{}
		require.NoError(t, UnmarshalConfig(cfg, viper.New(), writeConfig(t, yaml), true), name)
		csp := cfg.CAcfg.CSP
		require.NotNil(t, csp, name)
		require.Equal(t, "PQC", csp.Default, name)
		require.NotNil(t, csp.PQC, name)
		require.Equal(t, "msp/keystore", csp.PQC.KeyStorePath, name)
		require.Empty(t, csp.PQC.Password, name)
	}
}

// Classical configurations load as before, with and without a bccsp.sw
// section.
func TestUnmarshalConfigClassicalUnchanged(t *testing.T) {
	cfg := &ServerConfig{}
	require.NoError(t, UnmarshalConfig(cfg, viper.New(), writeConfig(t, "port: 7054\nbccsp:\n  default: SW\n  sw:\n    hash: SHA2\n    security: 256\n    filekeystore:\n      keystore: msp/keystore\n"), true))
	require.Equal(t, 7054, cfg.Port)
	csp := cfg.CAcfg.CSP
	require.NotNil(t, csp)
	require.Equal(t, "SW", csp.Default)
	require.Equal(t, "SHA2", csp.SW.Hash)
	require.Equal(t, 256, csp.SW.Security)
	require.Nil(t, csp.PQC)

	cfg = &ServerConfig{}
	require.NoError(t, UnmarshalConfig(cfg, viper.New(), writeConfig(t, "port: 7054\nca:\n  name: ca1\n"), true))
	require.Equal(t, 7054, cfg.Port)
	require.Equal(t, "ca1", cfg.CAcfg.CA.Name)
	require.Nil(t, cfg.CAcfg.CSP)
}
