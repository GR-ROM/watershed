// Package dialer opens backend connections over plain TCP or TLS.
package dialer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"watershed/internal/config"
)

// Dial connects to b, honouring its transport and TLS material.
func Dial(b config.Backend, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}

	switch b.Transport {
	case config.TransportPlain:
		conn, err := d.Dial("tcp", b.Addr)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", b.Addr, err)
		}
		return conn, nil

	case config.TransportTLS:
		cfg, err := TLSConfig(b)
		if err != nil {
			return nil, err
		}
		conn, err := tls.DialWithDialer(d, "tcp", b.Addr, cfg)
		if err != nil {
			return nil, fmt.Errorf("tls dial %s: %w", b.Addr, err)
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported transport %q", b.Transport)
	}
}

// TLSConfig builds the client-side tls.Config for a backend: a trust anchor
// from CACertFile (falling back to the system pool), an optional client
// certificate for mTLS, and a ServerName derived from the address.
func TLSConfig(b config.Backend) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: b.InsecureSkipVerify, //nolint:gosec // opt-in, dev only
	}

	// Verification uses the host part of the address unless it is an IP literal.
	if host, _, err := net.SplitHostPort(b.Addr); err == nil && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}

	if b.CACertFile != "" {
		pem, err := os.ReadFile(b.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", b.CACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %s contains no usable certificate", b.CACertFile)
		}
		cfg.RootCAs = pool
	}

	if b.UsesClientCert() {
		cert, err := tls.LoadX509KeyPair(b.ClientCertFile, b.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
