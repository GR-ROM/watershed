package inspector

import (
	"io"
	"strings"
	"testing"
	"time"
)

// peekString feeds s through a real socket and returns what Peek made of it.
func peekString(t *testing.T, s string, maxBytes int) (*Conn, Result) {
	t.Helper()

	client, server := pipeConns(t)
	go func() {
		_, _ = client.Write([]byte(s))
	}()

	conn, res, err := Peek(server, maxBytes, 2*time.Second)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	return conn, res
}

func TestParseRequestFields(t *testing.T) {
	raw := "POST /api/users?page=2 HTTP/1.1\r\n" +
		"Host: api.example.com:8443\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Token: abc\r\n" +
		"\r\n"

	_, res := peekString(t, raw, 4096)

	if res.Protocol != ProtocolHTTP {
		t.Fatalf("protocol = %v, want HTTP", res.Protocol)
	}
	r := res.Request
	if r == nil {
		t.Fatal("Request is nil for an HTTP stream")
	}
	if r.Partial {
		t.Error("Partial = true for a complete header block")
	}
	if r.Method != "POST" {
		t.Errorf("Method = %q, want POST", r.Method)
	}
	// The query string must be stripped so path rules stay simple.
	if r.Path != "/api/users" {
		t.Errorf("Path = %q, want /api/users", r.Path)
	}
	// The port must be stripped so host rules match the hostname alone.
	if r.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com", r.Host)
	}
	if got := r.Header["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type = %v", got)
	}
	if got := r.Header["X-Token"]; len(got) != 1 || got[0] != "abc" {
		t.Errorf("X-Token = %v", got)
	}
}

func TestParseAbsoluteFormTarget(t *testing.T) {
	raw := "GET http://example.com/some/path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	_, res := peekString(t, raw, 4096)

	if res.Request == nil {
		t.Fatal("Request is nil")
	}
	if res.Request.Path != "/some/path" {
		t.Errorf("Path = %q, want /some/path", res.Request.Path)
	}
}

func TestParseAbsoluteFormRoot(t *testing.T) {
	raw := "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
	_, res := peekString(t, raw, 4096)

	if res.Request == nil {
		t.Fatal("Request is nil")
	}
	if res.Request.Path != "/" {
		t.Errorf("Path = %q, want /", res.Request.Path)
	}
}

// TestParsePartialHeaders covers the case where the header block does not fit
// in the inspection budget: method and path must still be usable, and the
// result must admit that headers are incomplete.
func TestParsePartialHeaders(t *testing.T) {
	raw := "GET /api/thing HTTP/1.1\r\nHost: h\r\nX-Long: " + strings.Repeat("y", 500) + "\r\n\r\n"

	_, res := peekString(t, raw, 40) // deliberately smaller than the header block

	if res.Protocol != ProtocolHTTP {
		t.Fatalf("protocol = %v, want HTTP", res.Protocol)
	}
	r := res.Request
	if r == nil {
		t.Fatal("Request is nil")
	}
	if !r.Partial {
		t.Error("Partial = false although the header block was truncated")
	}
	if r.Method != "GET" {
		t.Errorf("Method = %q, want GET", r.Method)
	}
	if r.Path != "/api/thing" {
		t.Errorf("Path = %q, want /api/thing", r.Path)
	}
}

// TestBodyIsNotBuffered proves the peek stops at the end of the headers: the
// body must reach the backend through the tunnel, not through the buffer.
func TestBodyIsNotBuffered(t *testing.T) {
	body := strings.Repeat("b", 4000)
	raw := "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 4000\r\n\r\n" + body

	conn, res := peekString(t, raw, 4096)

	if res.Request == nil || res.Request.Method != "POST" {
		t.Fatalf("request not parsed: %+v", res.Request)
	}

	// Everything, headers and body alike, must still be readable in order.
	got, err := readN(conn, len(raw))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != raw {
		t.Fatalf("stream altered: got %d bytes, want %d", len(got), len(raw))
	}
}

func TestNonHTTPHasNoRequest(t *testing.T) {
	_, res := peekString(t, "\x16\x03\x01binary\n", 64)

	if res.Protocol != ProtocolTCP {
		t.Fatalf("protocol = %v, want TCP", res.Protocol)
	}
	if res.Request != nil {
		t.Errorf("Request = %+v, want nil for a non-HTTP stream", res.Request)
	}
}

func readN(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	for len(buf) < n {
		k, err := r.Read(tmp)
		buf = append(buf, tmp[:k]...)
		if err != nil {
			if err == io.EOF {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}
