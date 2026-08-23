// Package inspector peeks at the beginning of a decrypted stream to decide
// which backend a connection belongs to, without consuming those bytes.
package inspector

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// Protocol is the routing decision produced by Peek.
type Protocol int

const (
	// ProtocolTCP means "anything that is not recognisably HTTP".
	ProtocolTCP Protocol = iota
	// ProtocolHTTP means the stream opens with an HTTP request line.
	ProtocolHTTP
)

func (p Protocol) String() string {
	if p == ProtocolHTTP {
		return "http"
	}
	return "tcp"
}

// httpMethods are the request methods watershed recognises. The trailing space is
// part of the token: an HTTP request line is "<METHOD> <target> <version>".
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

// Detect reports whether prefix looks like the start of an HTTP request.
//
// It is deliberately conservative: a method token alone is not enough, because
// a raw TCP protocol could legitimately start with the letters "GET ". A full
// request line must also carry an " HTTP/" version token. When the line is not
// complete yet, a matching method is accepted as a provisional answer.
func Detect(prefix []byte) Protocol {
	method := matchMethod(prefix)
	if method == 0 {
		return ProtocolTCP
	}

	// Look at the first line only. Anything after CRLF belongs to headers.
	line := prefix
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
		line = bytes.TrimSuffix(line, []byte("\r"))
		// The line is complete, so we can demand a version token.
		if bytes.Contains(line[method:], []byte(" HTTP/")) {
			return ProtocolHTTP
		}
		return ProtocolTCP
	}

	// No newline yet. If the version token already arrived, we are certain.
	if bytes.Contains(line[method:], []byte(" HTTP/")) {
		return ProtocolHTTP
	}
	// Otherwise trust the method token: the request line is simply still in flight.
	return ProtocolHTTP
}

// matchMethod returns the length of the matched method token, or 0.
func matchMethod(prefix []byte) int {
	for _, m := range httpMethods {
		if bytes.HasPrefix(prefix, m) {
			return len(m)
		}
	}
	return 0
}

// Conn is a net.Conn whose first reads replay the bytes consumed by Peek.
// Everything else is delegated to the wrapped connection, so the proxy stays a
// transparent byte pipe once routing is decided.
type Conn struct {
	net.Conn
	prefix *bytes.Reader
}

// Read drains the peeked prefix first, then continues from the live connection.
func (c *Conn) Read(p []byte) (int, error) {
	if c.prefix != nil {
		if c.prefix.Len() > 0 {
			return c.prefix.Read(p)
		}
		c.prefix = nil
	}
	return c.Conn.Read(p)
}

// Peek reads whatever is immediately available at the head of conn, up to
// maxBytes or the first newline, and classifies it.
//
// It never waits for maxBytes to arrive: a short request must not stall the
// connection. The returned *Conn replays every peeked byte, so no data is lost
// or duplicated regardless of how much was buffered.
func Peek(conn net.Conn, maxBytes int, timeout time.Duration) (*Conn, Protocol, error) {
	if maxBytes <= 0 {
		return nil, ProtocolTCP, errors.New("inspector: maxBytes must be positive")
	}

	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, ProtocolTCP, err
		}
	}

	buf := make([]byte, 0, maxBytes)
	chunk := make([]byte, maxBytes)
	var readErr error

	for len(buf) < maxBytes {
		n, err := conn.Read(chunk[:maxBytes-len(buf)])
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			// One complete line is all the classifier needs.
			if bytes.IndexByte(buf, '\n') >= 0 {
				break
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}

	// Clear the deadline: from here on the connection is a long-lived tunnel.
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, ProtocolTCP, err
		}
	}

	// A timeout with bytes in hand is not fatal — we classify what we have. A
	// timeout with nothing at all means the client never spoke.
	if readErr != nil && len(buf) == 0 {
		if errors.Is(readErr, os.ErrDeadlineExceeded) {
			return nil, ProtocolTCP, errors.New("inspector: client sent no data before deadline")
		}
		if errors.Is(readErr, io.EOF) {
			return nil, ProtocolTCP, io.EOF
		}
		return nil, ProtocolTCP, readErr
	}

	return &Conn{Conn: conn, prefix: bytes.NewReader(buf)}, Detect(buf), nil
}
