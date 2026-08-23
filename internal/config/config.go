// Package config loads and validates watershed settings from environment variables.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"watershed/internal/router"
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
//
// The json tags serve the optional routes file, which may declare extra named
// backends beyond the two the environment configures.
type Backend struct {
	Transport          Transport `json:"type,omitempty"`
	Addr               string    `json:"addr"`
	CACertFile         string    `json:"caCertFile,omitempty"`
	ClientCertFile     string    `json:"clientCertFile,omitempty"`
	ClientKeyFile      string    `json:"clientKeyFile,omitempty"`
	InsecureSkipVerify bool      `json:"insecureSkipVerify,omitempty"`
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

	// HTTPBackend is where HTTP connections go when no rule matches, and
	// TCPBackend is where everything non-HTTP goes. Both are always present.
	HTTPBackend Backend
	TCPBackend  Backend

	// Backends holds every backend by name, including the two above under
	// DefaultHTTPBackendName and DefaultTCPBackendName, plus any declared in the
	// routes file. Rules address backends through this map.
	Backends map[string]Backend
	// Rules are evaluated in order for HTTP connections; the first match wins.
	// Empty means the proxy behaves exactly as it did before rules existed.
	Rules []router.Rule
	// RoutesFile records where the rules came from, for logging.
	RoutesFile string
}

// Names under which the environment-configured backends are registered.
const (
	DefaultHTTPBackendName = "http"
	DefaultTCPBackendName  = "tcp"
)

// routesFile is the on-disk shape of ROUTES_FILE.
type routesFile struct {
	Backends map[string]Backend `json:"backends"`
	Rules    []router.Rule      `json:"rules"`
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

	cfg.Backends = map[string]Backend{
		DefaultHTTPBackendName: cfg.HTTPBackend,
		DefaultTCPBackendName:  cfg.TCPBackend,
	}

	cfg.RoutesFile = os.Getenv("ROUTES_FILE")
	if cfg.RoutesFile != "" {
		if err := cfg.loadRoutes(cfg.RoutesFile); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// loadRoutes merges the routes file into cfg: extra named backends and the
// ordered rule list. Everything is validated here so a bad file fails at
// startup rather than on the first matching request.
func (cfg *Config) loadRoutes(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ROUTES_FILE: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a typo in a rule must not be silently ignored

	var rf routesFile
	if err := dec.Decode(&rf); err != nil {
		return fmt.Errorf("ROUTES_FILE %s: %w", path, err)
	}

	for name, b := range rf.Backends {
		if name == "" {
			return fmt.Errorf("ROUTES_FILE %s: a backend has an empty name", path)
		}
		if b.Addr == "" {
			return fmt.Errorf("ROUTES_FILE %s: backend %q has no addr", path, name)
		}
		if b.Transport == "" {
			b.Transport = TransportPlain
		}
		switch b.Transport {
		case TransportPlain, TransportTLS:
		default:
			return fmt.Errorf("ROUTES_FILE %s: backend %q has type %q, want %q or %q",
				path, name, b.Transport, TransportPlain, TransportTLS)
		}
		if (b.ClientCertFile == "") != (b.ClientKeyFile == "") {
			return fmt.Errorf("ROUTES_FILE %s: backend %q must set clientCertFile and clientKeyFile together",
				path, name)
		}
		if _, taken := cfg.Backends[name]; taken {
			return fmt.Errorf("ROUTES_FILE %s: backend %q collides with the environment-configured one",
				path, name)
		}
		cfg.Backends[name] = b
	}

	// Compile the rules purely to validate them; the proxy builds its own
	// Router from cfg.Rules at startup.
	if _, err := router.New(rf.Rules, func(name string) bool {
		_, ok := cfg.Backends[name]
		return ok
	}); err != nil {
		return fmt.Errorf("ROUTES_FILE %s: %w", path, err)
	}

	cfg.Rules = rf.Rules
	return nil
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
