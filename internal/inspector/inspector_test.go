package inspector

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Protocol
	}{
		{"real GET request", "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", ProtocolHTTP},
		{"POST with body", "POST /api HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi", ProtocolHTTP},
		{"root target", "GET / HTTP/1.0\r\n", ProtocolHTTP},
		{"absolute form", "GET http://example.com/ HTTP/1.1\r\n", ProtocolHTTP},
		{"partial request line", "GET /still-arri", ProtocolHTTP},
		{"method only", "OPTIONS ", ProtocolHTTP},

		{"empty", "", ProtocolTCP},
		{"binary", "\x00\x01\x02\x03rubbish", ProtocolTCP},
		{"redis PING", "*1\r\n$4\r\nPING\r\n", ProtocolTCP},
		{"looks like method but is not", "GETTING STARTED\r\n", ProtocolTCP},
		{"method without space", "GET/index HTTP/1.1\r\n", ProtocolTCP},
		{"complete line without version", "GET /index.html\r\nmore", ProtocolTCP},
		{"lowercase method", "get / HTTP/1.1\r\n", ProtocolTCP},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect([]byte(tc.in)); got != tc.want {
				t.Fatalf("Detect(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// pipeConns returns a connected pair backed by a real TCP socket, so deadlines
// and half-close behave exactly as they will in production.
func pipeConns(t *testing.T) (client, server net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}

	t.Cleanup(func() {
		client.Close()
		r.c.Close()
	})
	return client, r.c
}

// TestPeekShortPayloadDoesNotBlock is the regression test for the defect that
// made an earlier implementation hang: waiting for maxBytes to arrive when the
// client only ever sends a short request and then waits for a reply.
func TestPeekShortPayloadDoesNotBlock(t *testing.T) {
	client, server := pipeConns(t)

	const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() {
		_, _ = client.Write([]byte(req))
		// Deliberately no further writes and no close: the client is waiting
		// for a response, exactly like a real browser.
	}()

	done := make(chan struct{})
	var (
		res Result
		err error
	)
	go func() {
		defer close(done)
		_, res, err = Peek(server, 4096, 2*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Peek blocked on a short payload")
	}

	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Protocol != ProtocolHTTP {
		t.Fatalf("proto = %v, want %v", res.Protocol, ProtocolHTTP)
	}
}

// TestPeekReplaysEveryByte proves the proxy stays a faithful pipe: what Peek
// consumed is handed back verbatim, followed by the rest of the stream.
func TestPeekReplaysEveryByte(t *testing.T) {
	client, server := pipeConns(t)

	head := []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
	tail := bytes.Repeat([]byte("payload-"), 4096) // far beyond maxBytes

	go func() {
		_, _ = client.Write(head)
		_, _ = client.Write(tail)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	conn, res, err := Peek(server, 64, time.Second)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Protocol != ProtocolHTTP {
		t.Fatalf("proto = %v, want HTTP", res.Protocol)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	want := append(append([]byte{}, head...), tail...)
	if !bytes.Equal(got, want) {
		t.Fatalf("stream corrupted: got %d bytes, want %d (equal prefix %d)",
			len(got), len(want), commonPrefix(got, want))
	}
}

// TestPeekBinaryRoutesToTCP covers a non-HTTP protocol that never sends a newline.
func TestPeekBinaryRoutesToTCP(t *testing.T) {
	client, server := pipeConns(t)

	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x2f} // looks like a TLS record
	go func() { _, _ = client.Write(payload) }()

	conn, res, err := Peek(server, 8, time.Second)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Protocol != ProtocolTCP {
		t.Fatalf("proto = %v, want TCP", res.Protocol)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got % x, want % x", buf, payload)
	}
}

// TestPeekSilentClientTimesOut ensures a connection that never speaks is
// rejected instead of pinning a goroutine forever.
func TestPeekSilentClientTimesOut(t *testing.T) {
	_, server := pipeConns(t)

	start := time.Now()
	_, _, err := Peek(server, 4096, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error for a silent client")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Peek waited %s, expected to give up near the deadline", elapsed)
	}
}

// TestPeekClosedConnection covers a client that connects and immediately hangs up.
func TestPeekClosedConnection(t *testing.T) {
	client, server := pipeConns(t)
	client.Close()

	_, _, err := Peek(server, 4096, time.Second)
	if err == nil {
		t.Fatal("expected an error when the client closes immediately")
	}
	if !errors.Is(err, io.EOF) {
		t.Logf("error was %v (acceptable, EOF preferred)", err)
	}
}

func TestPeekRejectsBadMaxBytes(t *testing.T) {
	_, server := pipeConns(t)
	if _, _, err := Peek(server, 0, time.Second); err == nil {
		t.Fatal("expected an error for maxBytes = 0")
	}
}

func commonPrefix(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
