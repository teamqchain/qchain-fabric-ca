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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	libtls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/require"
)

const pqcTLSRefusal = "TLS without tls.keyfile is not supported when bccsp.default is PQC: set tls.certfile and tls.keyfile to an external ECDSA certificate and key"

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startTestServer starts the server newServer builds for a free port. The
// port is picked before the server binds it, so something else can take it
// in between; only that error is retried, with a new server on another port.
func startTestServer(t testing.TB, newServer func(port int) *Server) *Server {
	t.Helper()
	for attempt := 1; ; attempt++ {
		port := freePort(t)
		srv := newServer(port)
		err := srv.Start()
		if err == nil {
			t.Cleanup(func() { srv.Stop() })
			return srv
		}
		if !strings.Contains(err.Error(), "address already in use") || attempt == 5 {
			require.NoError(t, err)
		}
		// The server got as far as binding, so Stop can release what it set up.
		srv.Stop()
		t.Logf("port %d was taken before the server bound it; retrying on another port", port)
	}
}

// failRecorder stands in for the test in startTestServer so a failure can be
// observed: it records the failure and ends the goroutine, as FailNow does.
type failRecorder struct {
	testing.TB
	errs []string
}

func (r *failRecorder) Errorf(format string, args ...interface{}) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *failRecorder) FailNow() { runtime.Goexit() }

// runRecorded runs startTestServer with a failRecorder and returns the
// server, nil if startTestServer failed, and the recorded failures.
func runRecorded(t *testing.T, newServer func(port int) *Server) (*Server, []string) {
	rec := &failRecorder{TB: t}
	var srv *Server
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv = startTestServer(rec, newServer)
	}()
	<-done
	return srv, rec.errs
}

// The first port startTestServer picks is taken before the server binds it:
// the helper retries on another port and the server starts.
func TestStartTestServerRetriesTakenPort(t *testing.T) {
	var ports []int
	srv, errs := runRecorded(t, func(port int) *Server {
		ports = append(ports, port)
		if len(ports) == 1 {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			require.NoError(t, err)
			t.Cleanup(func() { l.Close() })
		}
		return getServer(port, t.TempDir(), "", -1, t)
	})
	require.Empty(t, errs)
	require.NotNil(t, srv)
	require.Len(t, ports, 2, "one retry")
	require.NotEqual(t, ports[0], ports[1])
	require.Equal(t, ports[1], srv.Config.Port)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports[1]))
	require.NoError(t, err, "the server listens on the second port")
	conn.Close()
}

// Any other Start error is not retried and fails at once.
func TestStartTestServerDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	srv, errs := runRecorded(t, func(port int) *Server {
		calls++
		return pqcTLSServer(t, t.TempDir(), "PQC", libtls.ServerTLSConfig{Enabled: true, CertFile: "tls-cert.pem"}, port)
	})
	require.Nil(t, srv)
	require.Equal(t, 1, calls, "no retry")
	require.Len(t, errs, 1)
	require.Contains(t, errs[0], pqcTLSRefusal)
}

func pqcTLSServer(t *testing.T, home, def string, tls libtls.ServerTLSConfig, port int) *Server {
	return &Server{
		HomeDir: home,
		Config:  &ServerConfig{Port: port, TLS: tls},
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
		srv := pqcTLSServer(t, home, def, libtls.ServerTLSConfig{Enabled: true, CertFile: "tls-cert.pem"}, freePort(t))
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
	srv := pqcTLSServer(t, home, "PQC", libtls.ServerTLSConfig{Enabled: true, CertFile: certFile}, freePort(t))
	err := srv.Start()
	if err == nil {
		srv.Stop()
	}
	require.EqualError(t, err, pqcTLSRefusal)
	entries, _ := os.ReadDir(home)
	require.Empty(t, entries)
}

// The guard does not refuse a PQC CA with external TLS files or with TLS
// disabled. With the pqc tag such a server starts; without it there is no
// PQC BCCSP, so Start fails in BCCSP initialization instead.
func TestServerStartAllowsPQCWithExternalTLSOrTLSOff(t *testing.T) {
	certFile, keyFile := writeECDSATLSFiles(t, t.TempDir())
	for name, tls := range map[string]libtls.ServerTLSConfig{
		"external ECDSA files": {Enabled: true, CertFile: certFile, KeyFile: keyFile},
		"TLS disabled":         {Enabled: false, CertFile: "tls-cert.pem"},
	} {
		if pqcBuild {
			// startTestServer fails the test unless the PQC CA starts.
			srv := startTestServer(t, func(port int) *Server { return pqcTLSServer(t, t.TempDir(), "PQC", tls, port) })
			require.NoError(t, srv.Stop(), name)
			continue
		}
		srv := pqcTLSServer(t, t.TempDir(), "PQC", tls, freePort(t))
		err := srv.Start()
		require.Error(t, err, name)
		require.False(t, strings.Contains(err.Error(), "TLS without tls.keyfile is not supported"), "%s: refused by the TLS guard: %v", name, err)
		require.Contains(t, err.Error(), "requires building with the pqc tag", name)
	}
}

// A classical CA still auto-generates an ECDSA TLS certificate.
func TestServerStartSWAutoGeneratesTLS(t *testing.T) {
	srv := startTestServer(t, func(port int) *Server {
		srv := getServer(port, t.TempDir(), "", -1, t)
		srv.Config.TLS.Enabled = true
		srv.Config.TLS.CertFile = "tls-cert.pem"
		return srv
	})

	data, err := os.ReadFile(filepath.Join(srv.HomeDir, "tls-cert.pem"))
	require.NoError(t, err, "the TLS certificate was auto-generated")
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "auto-generated TLS key is %T", cert.PublicKey)
}
