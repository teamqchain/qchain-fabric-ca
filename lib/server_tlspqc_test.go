/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	libtls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

const pqcTLSRefusal = "TLS without tls.keyfile is not supported when bccsp.default is PQC: set tls.certfile and tls.keyfile to an external ECDSA certificate and key"

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func pqcTLSServer(t *testing.T, home, def string, tls libtls.ServerTLSConfig) *Server {
	return &Server{
		HomeDir: home,
		Config:  &ServerConfig{Port: freePort(t), TLS: tls},
		CA:      CA{Config: &CAConfig{CSP: &factory.FactoryOpts{Default: def}}},
	}
}

// writeECDSATLSFiles mints a throwaway self-signed ECDSA P-256 TLS
// certificate and key in dir.
func writeECDSATLSFiles(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certFile, keyFile = filepath.Join(dir, "ecdsa-tls-cert.pem"), filepath.Join(dir, "ecdsa-tls-key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

func TestServerStartRefusesPQCTLSWithoutKeyFile(t *testing.T) {
	for _, def := range []string{"PQC", "pqc"} {
		home := t.TempDir()
		srv := pqcTLSServer(t, home, def, libtls.ServerTLSConfig{Enabled: true, CertFile: "tls-cert.pem"})
		err := srv.Start()
		if err == nil {
			srv.Stop()
		}
		require.EqualError(t, err, pqcTLSRefusal, "bccsp.default %q", def)
		entries, _ := os.ReadDir(home)
		require.Empty(t, entries, "nothing may be written to the home directory")
	}

	// A TLS certificate already on disk without a key file is refused too:
	// its key would be looked up in the PQC BCCSP.
	home := t.TempDir()
	certFile, _ := writeECDSATLSFiles(t, t.TempDir())
	srv := pqcTLSServer(t, home, "PQC", libtls.ServerTLSConfig{Enabled: true, CertFile: certFile})
	err := srv.Start()
	if err == nil {
		srv.Stop()
	}
	require.EqualError(t, err, pqcTLSRefusal)
	entries, _ := os.ReadDir(home)
	require.Empty(t, entries)
}

// The guard does not refuse a PQC CA with external TLS files or with TLS
// disabled. Start may still fail later in CA initialization; that is not
// this guard.
func TestServerStartAllowsPQCWithExternalTLSOrTLSOff(t *testing.T) {
	certFile, keyFile := writeECDSATLSFiles(t, t.TempDir())
	for name, tls := range map[string]libtls.ServerTLSConfig{
		"external ECDSA files": {Enabled: true, CertFile: certFile, KeyFile: keyFile},
		"TLS disabled":         {Enabled: false, CertFile: "tls-cert.pem"},
	} {
		srv := pqcTLSServer(t, t.TempDir(), "PQC", tls)
		err := srv.Start()
		if err == nil {
			require.NoError(t, srv.Stop())
			continue
		}
		require.False(t, strings.Contains(err.Error(), "TLS without tls.keyfile is not supported"), "%s: refused by the TLS guard: %v", name, err)
		t.Logf("%s: not refused by the TLS guard; Start stopped later with: %v", name, err)
	}
}

// A classical CA still auto-generates an ECDSA TLS certificate.
func TestServerStartSWAutoGeneratesTLS(t *testing.T) {
	home := t.TempDir()
	srv := getServer(freePort(t), home, "", -1, t)
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "tls-cert.pem"
	require.NoError(t, srv.Start())
	defer srv.Stop()

	data, err := os.ReadFile(filepath.Join(home, "tls-cert.pem"))
	require.NoError(t, err, "the TLS certificate was auto-generated")
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "auto-generated TLS key is %T", cert.PublicKey)
}
