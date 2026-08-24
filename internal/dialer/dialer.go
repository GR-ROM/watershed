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
	"watershed/internal/proxyproto"
)

// Dial connects to b, honouring its transport and TLS material.
//
// client and dialled describe the connection being proxied, from the client's point of view: who
// connected, and the address they connected to. They are only used when the backend asks for a PROXY
// header; pass nil for both when there is nothing to announce.
func Dial(b config.Backend, timeout time.Duration, client, dialled net.Addr) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}

	if b.Transport != config.TransportPlain && b.Transport != config.TransportTLS {
		return nil, fmt.Errorf("unsupported transport %q", b.Transport)
	}

	raw, err := d.Dial("tcp", b.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", b.Addr, err)
	}

	// Before the handshake, not after. The receiver reads it off the raw socket to decide whether
	// this client is welcome, which it has to know before spending a handshake on them.
	if b.SendProxy {
		if err := proxyproto.WriteV2(raw, client, dialled); err != nil {
			raw.Close()
			return nil, fmt.Errorf("announce %s: %w", b.Addr, err)
		}
	}

	if b.Transport == config.TransportPlain {
		return raw, nil
	}

	cfg, err := TLSConfig(b)
	if err != nil {
		raw.Close()
		return nil, err
	}
	// tls.DialWithDialer used to fill ServerName in from the dial address, including for an IP
	// literal, and TLSConfig leaves it empty on purpose for exactly that reason. Doing the handshake
	// by hand means doing that too, or an IP-addressed backend fails with "either ServerName or
	// InsecureSkipVerify must be specified" -- which is the shape of every backend here.
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		if host, _, splitErr := net.SplitHostPort(b.Addr); splitErr == nil {
			cfg.ServerName = host
		}
	}
	conn := tls.Client(raw, cfg)
	// tls.DialWithDialer bounded the handshake with the same timeout as the dial; doing it by hand
	// means bounding it by hand, or a backend that accepts and then says nothing holds this
	// goroutine and its two sockets forever.
	if timeout > 0 {
		if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls dial %s: %w", b.Addr, err)
		}
	}
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls dial %s: %w", b.Addr, err)
	}
	if timeout > 0 {
		if err := raw.SetDeadline(time.Time{}); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls dial %s: %w", b.Addr, err)
		}
	}
	return conn, nil
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
