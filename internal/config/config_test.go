package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setEnv applies vars for the duration of the test and clears everything else
// watershed reads, so tests cannot leak into each other.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()

	known := []string{
		"TLS_LISTEN_ADDR", "TLS_CERT_FILE", "TLS_KEY_FILE",
		"MAX_INSPECT_BYTES", "INSPECT_TIMEOUT", "DIAL_TIMEOUT",
		"BACKEND_HTTP_TYPE", "BACKEND_HTTP_ADDR", "BACKEND_HTTP_CA_CERT_FILE",
		"BACKEND_HTTP_CLIENT_CERT_FILE", "BACKEND_HTTP_CLIENT_KEY_FILE",
		"BACKEND_HTTP_TLS_INSECURE_SKIP_VERIFY",
		"BACKEND_TCP_TYPE", "BACKEND_TCP_ADDR", "BACKEND_TCP_CA_CERT_FILE",
		"BACKEND_TCP_CLIENT_CERT_FILE", "BACKEND_TCP_CLIENT_KEY_FILE",
		"BACKEND_TCP_TLS_INSECURE_SKIP_VERIFY",
	}
	for _, k := range known {
		t.Setenv(k, "")
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func touch(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func minimalEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"TLS_CERT_FILE":     touch(t, "cert.pem"),
		"TLS_KEY_FILE":      touch(t, "key.pem"),
		"BACKEND_HTTP_ADDR": "127.0.0.1:8080",
		"BACKEND_TCP_ADDR":  "127.0.0.1:9090",
	}
}

func TestLoadFromEnvDefaults(t *testing.T) {
	setEnv(t, minimalEnv(t))

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}

	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.MaxInspectBytes != DefaultMaxInspect {
		t.Errorf("MaxInspectBytes = %d, want %d", cfg.MaxInspectBytes, DefaultMaxInspect)
	}
	if cfg.InspectTimeout != DefaultInspectTimeout {
		t.Errorf("InspectTimeout = %s, want %s", cfg.InspectTimeout, DefaultInspectTimeout)
	}
	if cfg.HTTPBackend.Transport != TransportPlain || cfg.TCPBackend.Transport != TransportPlain {
		t.Errorf("default transports = %q/%q, want plain/plain",
			cfg.HTTPBackend.Transport, cfg.TCPBackend.Transport)
	}
}

func TestLoadFromEnvOverrides(t *testing.T) {
	env := minimalEnv(t)
	env["TLS_LISTEN_ADDR"] = ":9999"
	env["MAX_INSPECT_BYTES"] = "128"
	env["INSPECT_TIMEOUT"] = "250ms"
	env["DIAL_TIMEOUT"] = "3s"
	env["BACKEND_HTTP_TYPE"] = "TLS" // case must not matter
	env["BACKEND_HTTP_TLS_INSECURE_SKIP_VERIFY"] = "true"
	setEnv(t, env)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}

	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.MaxInspectBytes != 128 {
		t.Errorf("MaxInspectBytes = %d", cfg.MaxInspectBytes)
	}
	if cfg.InspectTimeout != 250*time.Millisecond {
		t.Errorf("InspectTimeout = %s", cfg.InspectTimeout)
	}
	if cfg.DialTimeout != 3*time.Second {
		t.Errorf("DialTimeout = %s", cfg.DialTimeout)
	}
	if cfg.HTTPBackend.Transport != TransportTLS {
		t.Errorf("HTTPBackend.Transport = %q, want tls", cfg.HTTPBackend.Transport)
	}
	if !cfg.HTTPBackend.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestLoadFromEnvErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing cert", func(e map[string]string) { delete(e, "TLS_CERT_FILE") }},
		{"missing key", func(e map[string]string) { delete(e, "TLS_KEY_FILE") }},
		{"missing http addr", func(e map[string]string) { delete(e, "BACKEND_HTTP_ADDR") }},
		{"missing tcp addr", func(e map[string]string) { delete(e, "BACKEND_TCP_ADDR") }},
		{"unknown transport", func(e map[string]string) { e["BACKEND_TCP_TYPE"] = "quic" }},
		{"non-numeric inspect bytes", func(e map[string]string) { e["MAX_INSPECT_BYTES"] = "12abc" }},
		{"zero inspect bytes", func(e map[string]string) { e["MAX_INSPECT_BYTES"] = "0" }},
		{"negative inspect bytes", func(e map[string]string) { e["MAX_INSPECT_BYTES"] = "-1" }},
		{"bad duration", func(e map[string]string) { e["DIAL_TIMEOUT"] = "soon" }},
		{"non-positive duration", func(e map[string]string) { e["INSPECT_TIMEOUT"] = "0s" }},
		{"bad bool", func(e map[string]string) {
			e["BACKEND_HTTP_TYPE"] = "tls"
			e["BACKEND_HTTP_TLS_INSECURE_SKIP_VERIFY"] = "maybe"
		}},
		{"client cert without key", func(e map[string]string) {
			e["BACKEND_HTTP_TYPE"] = "tls"
			e["BACKEND_HTTP_CLIENT_CERT_FILE"] = "/tmp/c.pem"
		}},
		{"client key without cert", func(e map[string]string) {
			e["BACKEND_HTTP_TYPE"] = "tls"
			e["BACKEND_HTTP_CLIENT_KEY_FILE"] = "/tmp/k.pem"
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := minimalEnv(t)
			tc.mutate(env)
			setEnv(t, env)

			if _, err := LoadFromEnv(); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// TestMalformedInspectBytesIsRejected pins the behaviour that a partially
// numeric value must fail loudly instead of being silently truncated to 12.
func TestMalformedInspectBytesIsRejected(t *testing.T) {
	env := minimalEnv(t)
	env["MAX_INSPECT_BYTES"] = "12abc"
	setEnv(t, env)

	cfg, err := LoadFromEnv()
	if err == nil {
		t.Fatalf("expected an error, got MaxInspectBytes = %d", cfg.MaxInspectBytes)
	}
}

func TestUsesClientCert(t *testing.T) {
	if (Backend{}).UsesClientCert() {
		t.Error("empty backend reported a client certificate")
	}
	if (Backend{ClientCertFile: "c"}).UsesClientCert() {
		t.Error("cert without key reported a client certificate")
	}
	if !(Backend{ClientCertFile: "c", ClientKeyFile: "k"}).UsesClientCert() {
		t.Error("cert and key together were not recognised")
	}
}
