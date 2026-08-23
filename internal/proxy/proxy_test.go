package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"watershed/internal/config"
)

// ---------------------------------------------------------------- test helpers

// issueCert writes a self-signed certificate valid for 127.0.0.1/localhost and
// returns the certificate and key paths.
func issueCert(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "watershed-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+"-key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

// startEcho runs a backend that prefixes every chunk it receives with tag, so a
// test can tell which backend answered.
func startEcho(t *testing.T, tag string, tlsCfg *tls.Config) string {
	t.Helper()

	var ln net.Listener
	var err error
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(append([]byte(tag), buf[:n]...)); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	return ln.Addr().String()
}

// startProxy boots a watershed server in front of the given backends.
func startProxy(t *testing.T, cfg *config.Config) string {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, log.New(io.Discard, "", 0))
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = ln.Close()
		srv.Shutdown(2 * time.Second)
	})

	return ln.Addr().String()
}

// dialProxy opens a TLS connection to the proxy, trusting the given CA file.
func dialProxy(t *testing.T, addr, caFile string) net.Conn {
	t.Helper()

	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("test CA did not parse")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readSome waits briefly for a reply and returns whatever arrived.
func readSome(t *testing.T, c net.Conn, want int) []byte {
	t.Helper()

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 0, want)
	tmp := make([]byte, 4096)
	for len(buf) < want {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return buf
}

func baseConfig(t *testing.T, httpAddr, tcpAddr string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := issueCert(t, dir, "proxy")

	return &config.Config{
		TLSCertFile:     certPath,
		TLSKeyFile:      keyPath,
		MaxInspectBytes: 4096,
		InspectTimeout:  2 * time.Second,
		DialTimeout:     2 * time.Second,
		HTTPBackend:     config.Backend{Transport: config.TransportPlain, Addr: httpAddr},
		TCPBackend:      config.Backend{Transport: config.TransportPlain, Addr: tcpAddr},
	}
}

// ---------------------------------------------------------------------- tests

// TestRoutesHTTPToWebBackend is the core routing contract.
func TestRoutesHTTPToWebBackend(t *testing.T) {
	httpAddr := startEcho(t, "WEB:", nil)
	tcpAddr := startEcho(t, "TCP:", nil)
	cfg := baseConfig(t, httpAddr, tcpAddr)
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	req := "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	got := readSome(t, conn, len("WEB:")+len(req))
	if !bytes.HasPrefix(got, []byte("WEB:")) {
		t.Fatalf("HTTP request went to the wrong backend: %q", got)
	}
	if !bytes.Contains(got, []byte(req)) {
		t.Fatalf("request body was altered in transit: %q", got)
	}
}

// TestRoutesNonHTTPToTCPBackend covers the other branch of the decision.
func TestRoutesNonHTTPToTCPBackend(t *testing.T) {
	httpAddr := startEcho(t, "WEB:", nil)
	tcpAddr := startEcho(t, "TCP:", nil)
	cfg := baseConfig(t, httpAddr, tcpAddr)
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	payload := []byte{0x00, 0x01, 0xff, 0xfe, 'h', 'i'}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	got := readSome(t, conn, len("TCP:")+len(payload))
	if !bytes.HasPrefix(got, []byte("TCP:")) {
		t.Fatalf("binary payload went to the wrong backend: %q", got)
	}
	if !bytes.Contains(got, payload) {
		t.Fatalf("payload was altered in transit: % x", got)
	}
}

// TestLargePayloadIntegrity proves the tunnel is byte-exact well past the
// inspection buffer, in both directions.
func TestLargePayloadIntegrity(t *testing.T) {
	tcpAddr := startEcho(t, "", nil) // no tag: pure echo
	cfg := baseConfig(t, tcpAddr, tcpAddr)
	cfg.MaxInspectBytes = 64 // force the payload to dwarf the peek buffer
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)

	payload := make([]byte, 512*1024)
	for i := range payload {
		payload[i] = byte(i % 251) // non-repeating pattern catches offset errors
	}

	go func() {
		_, _ = conn.Write(payload)
	}()

	got := readSome(t, conn, len(payload))
	if len(got) != len(payload) {
		t.Fatalf("echoed %d bytes, sent %d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("stream diverged at byte %d: got %d, want %d", i, got[i], payload[i])
			}
		}
	}
}

// TestTLSBackend exercises the encrypted upstream path with real verification
// against a CA bundle.
func TestTLSBackend(t *testing.T) {
	dir := t.TempDir()
	beCert, beKey := issueCert(t, dir, "backend")

	pair, err := tls.LoadX509KeyPair(beCert, beKey)
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := startEcho(t, "TLSWEB:", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	tcpAddr := startEcho(t, "TCP:", nil)

	cfg := baseConfig(t, httpAddr, tcpAddr)
	cfg.HTTPBackend = config.Backend{
		Transport:  config.TransportTLS,
		Addr:       httpAddr,
		CACertFile: beCert, // self-signed: the leaf is its own trust anchor
	}
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	req := "POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	got := readSome(t, conn, len("TLSWEB:")+len(req))
	if !bytes.HasPrefix(got, []byte("TLSWEB:")) {
		t.Fatalf("TLS backend did not answer: %q", got)
	}
}

// TestUnreachableBackendClosesClient makes sure a dead upstream is a clean
// disconnect rather than a hang.
func TestUnreachableBackendClosesClient(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close() // nothing listens here now

	cfg := baseConfig(t, deadAddr, deadAddr)
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed, but data arrived")
	}
}

// TestShutdownReleasesConnections checks the graceful path terminates.
func TestShutdownReleasesConnections(t *testing.T) {
	tcpAddr := startEcho(t, "", nil)
	cfg := baseConfig(t, tcpAddr, tcpAddr)

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, log.New(io.Discard, "", 0))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	conn := dialProxy(t, ln.Addr().String(), cfg.TLSCertFile)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	readSome(t, conn, 5)

	_ = ln.Close()
	start := time.Now()
	srv.Shutdown(3 * time.Second)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Shutdown took %s, expected it to finish within the grace period", elapsed)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the listener closed")
	}
}
