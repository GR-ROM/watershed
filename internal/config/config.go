// Package config loads and validates watershed settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Transport selects how the proxy connects to a backend.
type Transport string

const (
	// TransportPlain dials the backend over plain TCP.
	TransportPlain Transport = "plain"
	// TransportTLS dials the backend over TLS, optionally with a client certificate.
	TransportTLS Transport = "tls"
)

// Backend describes one downstream target and how to reach it.
type Backend struct {
	Transport          Transport
	Addr               string
	CACertFile         string
	ClientCertFile     string
	ClientKeyFile      string
	InsecureSkipVerify bool
}

// UsesClientCert reports whether a client certificate was configured for mTLS.
func (b Backend) UsesClientCert() bool {
	return b.ClientCertFile != "" && b.ClientKeyFile != ""
}

// Config is the fully validated runtime configuration.
type Config struct {
	ListenAddr  string
	TLSCertFile string
	TLSKeyFile  string

	// MaxInspectBytes caps how much of the decrypted stream is buffered while
	// deciding which backend to use.
	MaxInspectBytes int
	// InspectTimeout bounds how long the proxy waits for those first bytes, so a
	// client that connects and stays silent cannot pin a goroutine forever.
	InspectTimeout time.Duration
	// DialTimeout bounds establishing the backend connection.
	DialTimeout time.Duration

	HTTPBackend Backend
	TCPBackend  Backend
}

// Defaults applied when the corresponding variable is unset or empty.
const (
	DefaultListenAddr     = ":4430"
	DefaultMaxInspect     = 4096
	DefaultInspectTimeout = 5 * time.Second
	DefaultDialTimeout    = 10 * time.Second
)

// LoadFromEnv builds a Config from the process environment.
//
// It never panics: every problem is reported as an error so the caller decides
// how to fail.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:  envOr("TLS_LISTEN_ADDR", DefaultListenAddr),
		TLSCertFile: os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("TLS_KEY_FILE"),
	}

	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required: the proxy terminates client TLS")
	}

	var err error
	if cfg.MaxInspectBytes, err = envInt("MAX_INSPECT_BYTES", DefaultMaxInspect); err != nil {
		return nil, err
	}
	if cfg.MaxInspectBytes <= 0 {
		return nil, fmt.Errorf("MAX_INSPECT_BYTES must be positive, got %d", cfg.MaxInspectBytes)
	}

	if cfg.InspectTimeout, err = envDuration("INSPECT_TIMEOUT", DefaultInspectTimeout); err != nil {
		return nil, err
	}
	if cfg.DialTimeout, err = envDuration("DIAL_TIMEOUT", DefaultDialTimeout); err != nil {
		return nil, err
	}

	if cfg.HTTPBackend, err = loadBackend("BACKEND_HTTP"); err != nil {
		return nil, err
	}
	if cfg.TCPBackend, err = loadBackend("BACKEND_TCP"); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadBackend reads one BACKEND_<NAME>_* group.
func loadBackend(prefix string) (Backend, error) {
	b := Backend{
		Transport:      Transport(strings.ToLower(envOr(prefix+"_TYPE", string(TransportPlain)))),
		Addr:           os.Getenv(prefix + "_ADDR"),
		CACertFile:     os.Getenv(prefix + "_CA_CERT_FILE"),
		ClientCertFile: os.Getenv(prefix + "_CLIENT_CERT_FILE"),
		ClientKeyFile:  os.Getenv(prefix + "_CLIENT_KEY_FILE"),
	}

	if b.Addr == "" {
		return Backend{}, fmt.Errorf("%s_ADDR is required", prefix)
	}

	switch b.Transport {
	case TransportPlain:
		// TLS-only fields are ignored on purpose, so a half-edited environment
		// cannot silently change the transport.
	case TransportTLS:
		var err error
		if b.InsecureSkipVerify, err = envBool(prefix+"_TLS_INSECURE_SKIP_VERIFY", false); err != nil {
			return Backend{}, err
		}
		if (b.ClientCertFile == "") != (b.ClientKeyFile == "") {
			return Backend{}, fmt.Errorf(
				"%s_CLIENT_CERT_FILE and %s_CLIENT_KEY_FILE must be set together", prefix, prefix)
		}
	default:
		return Backend{}, fmt.Errorf("%s_TYPE must be %q or %q, got %q",
			prefix, TransportPlain, TransportTLS, b.Transport)
	}

	return b, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", key, d)
	}
	return d, nil
}

func envBool(key string, def bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return v, nil
}
