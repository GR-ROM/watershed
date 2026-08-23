package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRoutes drops a routes file into a temp dir and returns its path.
func writeRoutes(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadWithRoutes(t *testing.T, body string) (*Config, error) {
	t.Helper()
	env := minimalEnv(t)
	env["ROUTES_FILE"] = writeRoutes(t, body)
	setEnv(t, env)
	return LoadFromEnv()
}

func TestRoutesFileLoads(t *testing.T) {
	cfg, err := loadWithRoutes(t, `{
	  "backends": {
	    "api": {"addr": "127.0.0.1:9001"},
	    "cdn": {"addr": "127.0.0.1:9002", "type": "tls", "insecureSkipVerify": true}
	  },
	  "rules": [
	    {"name": "api", "backend": "api", "path": {"prefix": "/api/"}},
	    {"name": "assets", "backend": "cdn", "path": {"suffix": ".js"}},
	    {"name": "writes", "backend": "api", "methods": ["POST", "PUT"]},
	    {"name": "canary", "backend": "cdn",
	     "headers": [{"name": "X-Canary", "equals": "1"}]}
	  ]
	}`)
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}

	if len(cfg.Rules) != 4 {
		t.Fatalf("loaded %d rules, want 4", len(cfg.Rules))
	}

	// The two environment backends plus the two from the file.
	for _, name := range []string{DefaultHTTPBackendName, DefaultTCPBackendName, "api", "cdn"} {
		if _, ok := cfg.Backends[name]; !ok {
			t.Errorf("backend %q missing", name)
		}
	}

	if cfg.Backends["api"].Transport != TransportPlain {
		t.Errorf("api transport = %q, want plain by default", cfg.Backends["api"].Transport)
	}
	cdn := cfg.Backends["cdn"]
	if cdn.Transport != TransportTLS || !cdn.InsecureSkipVerify {
		t.Errorf("cdn = %+v, want tls with insecureSkipVerify", cdn)
	}
}

func TestNoRoutesFileKeepsOldBehaviour(t *testing.T) {
	setEnv(t, minimalEnv(t))

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("got %d rules without ROUTES_FILE, want none", len(cfg.Rules))
	}
	if len(cfg.Backends) != 2 {
		t.Errorf("got %d backends, want just the two from the environment", len(cfg.Backends))
	}
}

func TestRoutesFileErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"rules": [`},
		{"unknown field", `{"rules": [{"backend": "http", "pathx": {"prefix": "/"}}]}`},
		{"unknown backend", `{"rules": [{"backend": "ghost", "path": {"prefix": "/"}}]}`},
		{"backend without addr", `{"backends": {"api": {}},
		  "rules": [{"backend": "api", "path": {"prefix": "/"}}]}`},
		{"bad transport", `{"backends": {"api": {"addr": "x:1", "type": "quic"}},
		  "rules": [{"backend": "api", "path": {"prefix": "/"}}]}`},
		{"cert without key", `{"backends": {"api": {"addr": "x:1", "type": "tls",
		  "clientCertFile": "/c.pem"}}, "rules": [{"backend": "api", "path": {"prefix": "/"}}]}`},
		{"rule without conditions", `{"rules": [{"backend": "http"}]}`},
		{"bad regex", `{"rules": [{"backend": "http", "path": {"regex": "([a-z"}}]}`},
		{"two match kinds", `{"rules": [{"backend": "http",
		  "path": {"equals": "/a", "prefix": "/b"}}]}`},
		{"name collides with default", `{"backends": {"http": {"addr": "x:1"}},
		  "rules": [{"backend": "http", "path": {"prefix": "/"}}]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadWithRoutes(t, tc.body); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestRoutesFileMissing(t *testing.T) {
	env := minimalEnv(t)
	env["ROUTES_FILE"] = filepath.Join(t.TempDir(), "absent.json")
	setEnv(t, env)

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected an error for a missing routes file")
	}
}

// TestRulesMayTargetDefaultBackends: rules should be able to point at the
// environment-configured backends by name, not only at file-declared ones.
func TestRulesMayTargetDefaultBackends(t *testing.T) {
	cfg, err := loadWithRoutes(t, `{
	  "rules": [{"backend": "tcp", "path": {"prefix": "/raw/"}}]
	}`)
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Backend != DefaultTCPBackendName {
		t.Fatalf("rules = %+v", cfg.Rules)
	}
}
