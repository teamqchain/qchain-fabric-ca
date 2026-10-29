/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The client refuses a bccsp.pqc.password in its configuration file before
// decoding it, in every build, without showing the password. Without the
// password the same file loads and the command fails later, at the
// connection.
func TestClientConfigRefusesPQCPassword(t *testing.T) {
	const password = "dummy-pqc-pw-7f3a"
	run := func(yaml string) (string, error) {
		home := t.TempDir()
		cfgFile := filepath.Join(home, "fabric-ca-client-config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yaml), 0o600))
		return cfgFile, RunMain([]string{cmdName, "getcainfo", "-H", home, "-u", "http://localhost:1"})
	}

	cfgFile, err := run("bccsp:\n  default: PQC\n  pqc:\n    password: " + password + "\n")
	if err == nil {
		t.Fatal("the configuration loaded")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatal("the error contains the password")
	}
	want := "Invalid configuration in file '" + cfgFile + "': bccsp.pqc.password is not supported: the PQC BCCSP stores ML-DSA private keys unencrypted; remove the password"
	if err.Error() != want {
		t.Fatalf("the error is not %q (it is %d bytes long)", want, len(err.Error()))
	}

	for name, yaml := range map[string]string{
		"PQC without password": "bccsp:\n  default: PQC\n",
		"SW with a sw section": "bccsp:\n  default: SW\n  sw:\n    hash: SHA2\n    security: 256\n",
		"no bccsp section":     "url: http://localhost:1\n",
	} {
		_, err := run(yaml)
		require.Error(t, err, name)
		require.NotContains(t, err.Error(), "Invalid configuration in file", name)
		require.NotContains(t, err.Error(), "Incorrect format in file", name)
	}
}
