package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"testing"
	"time"

	"watershed/internal/config"
	"watershed/internal/router"
)

// ruleConfig builds a config with named backends and a rule set.
func ruleConfig(t *testing.T, backends map[string]string, rules []router.Rule) *config.Config {
	t.Helper()

	dir := t.TempDir()
	certPath, keyPath := issueCert(t, dir, "proxy")

	named := map[string]config.Backend{}
	for name, addr := range backends {
		named[name] = config.Backend{Transport: config.TransportPlain, Addr: addr}
	}

	cfg := &config.Config{
		TLSCertFile:     certPath,
		TLSKeyFile:      keyPath,
		MaxInspectBytes: 4096,
		InspectTimeout:  2 * time.Second,
		DialTimeout:     2 * time.Second,
		HTTPBackend:     named[config.DefaultHTTPBackendName],
		TCPBackend:      named[config.DefaultTCPBackendName],
		Backends:        named,
		Rules:           rules,
	}
	return cfg
}

// startRuleProxy boots a server and returns its address.
func startRuleProxy(t *testing.T, cfg *config.Config) string {
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

	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		srv.Shutdown(2 * time.Second)
	})

	return ln.Addr().String()
}

// whoAnswered sends raw and reports the tag the responding backend prefixed.
//
// It reads only until the tag separator instead of waiting for a fixed byte
// count: tags differ in length, so counting bytes would stall on every call
// until the read deadline expired.
func whoAnswered(t *testing.T, addr, caFile, raw string) string {
	t.Helper()

	conn := dialProxy(t, addr, caFile)
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var got []byte
	tmp := make([]byte, 512)
	for {
		n, err := conn.Read(tmp)
		got = append(got, tmp[:n]...)
		if i := bytes.IndexByte(got, ':'); i >= 0 {
			return string(got[:i])
		}
		if err != nil {
			t.Fatalf("no backend tag in reply %q: %v", got, err)
		}
	}
}

// TestRuleRoutingEndToEnd drives every match kind through the real proxy.
func TestRuleRoutingEndToEnd(t *testing.T) {
	def := startEcho(t, "DEFAULT:", nil)
	api := startEcho(t, "API:", nil)
	cdn := startEcho(t, "CDN:", nil)
	canary := startEcho(t, "CANARY:", nil)
	tcpBe := startEcho(t, "TCP:", nil)

	cfg := ruleConfig(t,
		map[string]string{
			config.DefaultHTTPBackendName: def,
			config.DefaultTCPBackendName:  tcpBe,
			"api":                         api,
			"cdn":                         cdn,
			"canary":                      canary,
		},
		[]router.Rule{
			{Name: "canary", Backend: "canary", Headers: []router.HeaderMatch{
				{Name: "X-Canary", StringMatch: router.StringMatch{Equals: "1"}},
			}},
			{Name: "writes", Backend: "api", Methods: []string{"POST", "PUT"}},
			{Name: "api-path", Backend: "api", Path: &router.StringMatch{Prefix: "/api/"}},
			{Name: "assets", Backend: "cdn", Path: &router.StringMatch{Suffix: ".js"}},
			{Name: "by-host", Backend: "cdn", Host: &router.StringMatch{Equals: "static.example.com"}},
		})

	addr := startRuleProxy(t, cfg)

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"path prefix", "GET /api/users HTTP/1.1\r\nHost: h\r\n\r\n", "API"},
		{"method", "POST /anything HTTP/1.1\r\nHost: h\r\n\r\n", "API"},
		{"suffix", "GET /static/app.js HTTP/1.1\r\nHost: h\r\n\r\n", "CDN"},
		{"host", "GET /img.png HTTP/1.1\r\nHost: static.example.com\r\n\r\n", "CDN"},
		{"header wins by order", "GET /api/x HTTP/1.1\r\nHost: h\r\nX-Canary: 1\r\n\r\n", "CANARY"},
		{"no rule matches", "GET /other HTTP/1.1\r\nHost: h\r\n\r\n", "DEFAULT"},
		{"non-http ignores rules", "\x00\x01binary\n", "TCP"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := whoAnswered(t, addr, cfg.TLSCertFile, tc.raw); got != tc.want {
				t.Fatalf("answered by %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRuleOrderDecides pins that the first matching rule wins end to end, not
// just in the router unit test.
func TestRuleOrderDecides(t *testing.T) {
	def := startEcho(t, "DEFAULT:", nil)
	first := startEcho(t, "FIRST:", nil)
	second := startEcho(t, "SECOND:", nil)
	tcpBe := startEcho(t, "TCP:", nil)

	cfg := ruleConfig(t,
		map[string]string{
			config.DefaultHTTPBackendName: def,
			config.DefaultTCPBackendName:  tcpBe,
			"first":                       first,
			"second":                      second,
		},
		[]router.Rule{
			{Backend: "first", Path: &router.StringMatch{Prefix: "/api/v2/"}},
			{Backend: "second", Path: &router.StringMatch{Prefix: "/api/"}},
		})

	addr := startRuleProxy(t, cfg)

	if got := whoAnswered(t, addr, cfg.TLSCertFile, "GET /api/v2/x HTTP/1.1\r\nHost: h\r\n\r\n"); got != "FIRST" {
		t.Fatalf("answered by %q, want FIRST", got)
	}
	if got := whoAnswered(t, addr, cfg.TLSCertFile, "GET /api/v1/x HTTP/1.1\r\nHost: h\r\n\r\n"); got != "SECOND" {
		t.Fatalf("answered by %q, want SECOND", got)
	}
}

// TestBrokenRuleSetFailsAtStartup: a rule pointing at a backend that does not
// exist must stop the server from starting, not fail one request later.
func TestBrokenRuleSetFailsAtStartup(t *testing.T) {
	be := startEcho(t, "X:", nil)
	cfg := ruleConfig(t,
		map[string]string{
			config.DefaultHTTPBackendName: be,
			config.DefaultTCPBackendName:  be,
		},
		[]router.Rule{{Backend: "nonexistent", Path: &router.StringMatch{Prefix: "/"}}})

	if _, err := New(cfg, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("New accepted a rule pointing at an unknown backend")
	}
}

// TestBodyReachesRuleSelectedBackend checks the tunnel stays intact after the
// header block was buffered for matching: the body must arrive unaltered.
func TestBodyReachesRuleSelectedBackend(t *testing.T) {
	def := startEcho(t, "DEFAULT:", nil)
	api := startEcho(t, "", nil) // untagged, so the echo is byte-exact
	tcpBe := startEcho(t, "TCP:", nil)

	cfg := ruleConfig(t,
		map[string]string{
			config.DefaultHTTPBackendName: def,
			config.DefaultTCPBackendName:  tcpBe,
			"api":                         api,
		},
		[]router.Rule{{Backend: "api", Path: &router.StringMatch{Prefix: "/upload"}}})

	addr := startRuleProxy(t, cfg)

	body := bytes.Repeat([]byte("z"), 100000)
	head := "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 100000\r\n\r\n"
	full := append([]byte(head), body...)

	conn := dialProxy(t, addr, cfg.TLSCertFile)
	go func() { _, _ = conn.Write(full) }()

	got := readSome(t, conn, len(full))
	if len(got) != len(full) {
		t.Fatalf("echoed %d bytes, sent %d", len(got), len(full))
	}
	if !bytes.Equal(got, full) {
		t.Fatal("stream altered between client and rule-selected backend")
	}
}
