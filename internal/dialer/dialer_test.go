package dialer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

	"watershed/internal/config"
)

func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dialer-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "c.pem")
	keyPath = filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestDialPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("ok"))
			c.Close()
		}
	}()

	conn, err := Dial(config.Backend{Transport: config.TransportPlain, Addr: ln.Addr().String()}, time.Second, nil, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("got %q", buf)
	}
}

func TestDialTLSVerifiesAgainstCABundle(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = c.Write([]byte("tls-ok")); c.Close() }(c)
		}
	}()

	t.Run("trusted CA succeeds", func(t *testing.T) {
		conn, err := Dial(config.Backend{
			Transport:  config.TransportTLS,
			Addr:       ln.Addr().String(),
			CACertFile: certPath,
		}, 2*time.Second, nil, nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 6)
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(buf) != "tls-ok" {
			t.Fatalf("got %q", buf)
		}
	})

	t.Run("untrusted certificate is rejected", func(t *testing.T) {
		_, err := Dial(config.Backend{
			Transport: config.TransportTLS,
			Addr:      ln.Addr().String(),
		}, 2*time.Second, nil, nil)
		if err == nil {
			t.Fatal("expected verification to fail without the CA bundle")
		}
	})

	t.Run("insecure skip verify bypasses it", func(t *testing.T) {
		conn, err := Dial(config.Backend{
			Transport:          config.TransportTLS,
			Addr:               ln.Addr().String(),
			InsecureSkipVerify: true,
		}, 2*time.Second, nil, nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		conn.Close()
	})
}

func TestTLSConfigErrors(t *testing.T) {
	t.Run("missing CA file", func(t *testing.T) {
		_, err := TLSConfig(config.Backend{
			Transport:  config.TransportTLS,
			Addr:       "127.0.0.1:1",
			CACertFile: filepath.Join(t.TempDir(), "absent.pem"),
		})
		if err == nil {
			t.Fatal("expected an error for a missing CA file")
		}
	})

	t.Run("CA file without certificates", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(p, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := TLSConfig(config.Backend{
			Transport: config.TransportTLS, Addr: "127.0.0.1:1", CACertFile: p,
		}); err == nil {
			t.Fatal("expected an error for a bundle with no certificates")
		}
	})

	t.Run("server name from hostname", func(t *testing.T) {
		cfg, err := TLSConfig(config.Backend{Transport: config.TransportTLS, Addr: "backend.internal:8443"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != "backend.internal" {
			t.Fatalf("ServerName = %q, want backend.internal", cfg.ServerName)
		}
	})

	t.Run("no server name for IP literal", func(t *testing.T) {
		cfg, err := TLSConfig(config.Backend{Transport: config.TransportTLS, Addr: "10.0.0.5:8443"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != "" {
			t.Fatalf("ServerName = %q, want empty for an IP literal", cfg.ServerName)
		}
	})
}

func TestDialUnsupportedTransport(t *testing.T) {
	if _, err := Dial(config.Backend{Transport: "quic", Addr: "127.0.0.1:1"}, time.Second, nil, nil); err == nil {
		t.Fatal("expected an error for an unsupported transport")
	}
}

func TestDialResumingRefusesAnUnknownTransport(t *testing.T) {
	// A backend the config parser did not vet must fail before a socket is opened, not after.
	_, err := DialResuming(config.Backend{Transport: "carrier-pigeon", Addr: "127.0.0.1:1"},
		time.Second, nil, nil)
	if err == nil {
		t.Fatal("an unsupported transport must not dial")
	}
	if !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("the error must name the transport, got %v", err)
	}
}

func TestDialResumingReportsAnUnreachableBackend(t *testing.T) {
	// Nothing listens here: a failed re-dial mid-rollout has to surface, or the session is silently
	// left on the instance that is about to stop.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if _, err := DialResuming(config.Backend{Transport: config.TransportPlain, Addr: addr},
		200*time.Millisecond, nil, nil); err == nil {
		t.Fatal("dialling a closed port must fail")
	}
}

func TestDialResumingBoundsATlsBackendThatNeverAnswers(t *testing.T) {
	// A backend that accepts and then says nothing used to hold the goroutine and both sockets for
	// ever; the handshake deadline is what stops one dead backend from leaking the whole rollout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()

	start := time.Now()
	_, err = DialResuming(config.Backend{Transport: config.TransportTLS, Addr: ln.Addr().String(),
		InsecureSkipVerify: true}, 150*time.Millisecond, nil, nil)
	if err == nil {
		t.Fatal("a silent TLS backend must not hang the dial")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the handshake was not bounded: took %s", elapsed)
	}
}
