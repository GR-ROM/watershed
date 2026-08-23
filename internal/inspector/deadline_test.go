package inspector

import (
	"bytes"
	"testing"
	"time"
)

// A binary protocol has no reason to send a newline, and a client that sends one
// short frame and waits for a reply sends nothing more. Until 2026-08-23 Peek only
// classified once a '\n' turned up in the buffer, so such a connection was held
// until the read deadline fired and every one of them paid the whole
// INSPECT_TIMEOUT before a byte reached the backend. Measured through a real
// proxy: 5266 ms to the first protocol reply at the 5 s default, 773 ms at 500 ms.
func TestPeekDoesNotWaitOutTheDeadlineForBinaryStreams(t *testing.T) {
	client, server := pipeConns(t)

	// A MyVPN frame header: 4-byte big-endian length, then msgpack. No newline.
	frame := []byte{0x00, 0x00, 0x00, 0x10, 0x81, 0xA5, 'h', 'e', 'l', 'l', 'o'}
	go func() {
		client.Write(frame)
		// and then nothing, like a client waiting for its answer
	}()

	const timeout = 2 * time.Second
	start := time.Now()
	conn, res, err := Peek(server, 4096, timeout)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Protocol != ProtocolTCP {
		t.Fatalf("Protocol = %v, want %v", res.Protocol, ProtocolTCP)
	}
	if elapsed > timeout/2 {
		t.Fatalf("Peek took %v with a %v deadline: it waited for the deadline instead of "+
			"classifying on the first bytes", elapsed, timeout)
	}

	// Every peeked byte must still be replayed to the backend.
	got := make([]byte, len(frame))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("replay read: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("replayed % x, want % x", got, frame)
	}
}

// The other half of the same decision: a prefix that is still a partial method
// token has to keep waiting, or "GE" would be misrouted before "GET " arrives.
func TestCouldBeHTTP(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"", true},
		{"G", true},
		{"GE", true},
		{"GET", true},
		{"GET ", true},
		{"GET /index.html HTTP/1.1", true},
		{"OPTION", true},
		{"PROPFIND ", false}, // not in the table: watershed does not claim WebDAV
		{"\x00\x00\x00\x10", false},
		{"\x16\x03\x01", false}, // a TLS record, which is what a nested handshake looks like
		{"GETX", false},
		{"X", false},
	}
	for _, c := range cases {
		if got := couldBeHTTP([]byte(c.prefix)); got != c.want {
			t.Errorf("couldBeHTTP(%q) = %v, want %v", c.prefix, got, c.want)
		}
	}
}
