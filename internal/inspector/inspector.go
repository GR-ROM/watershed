// Package inspector peeks at the beginning of a decrypted stream to decide
// which backend a connection belongs to, without consuming those bytes.
package inspector

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Protocol is the coarse routing decision.
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

// Request carries the parts of an HTTP request that rules can match on.
// It is only populated when Protocol is ProtocolHTTP.
type Request struct {
	Method string
	Path   string
	Host   string
	Header map[string][]string
	// Partial is true when the header block did not fully arrive before the
	// size or time limit. Method and Path stay trustworthy; Header may be
	// incomplete, so a header rule can produce a false negative.
	Partial bool
}

// Result is what Peek learned about a connection.
type Result struct {
	Protocol Protocol
	Request  *Request
}

// httpMethods are the request methods watershed recognises. The trailing space
// is part of the token: a request line is "<METHOD> <target> <version>".
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

var headerTerminators = [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")}

// Detect reports whether prefix looks like the start of an HTTP request.
//
// It is deliberately conservative: a method token alone is not enough, because
// a raw TCP protocol could legitimately start with the letters "GET ". A full
// request line must also carry an " HTTP/" version token. When the line has not
// arrived in full, a matching method is accepted as a provisional answer.
func Detect(prefix []byte) Protocol {
	method := matchMethod(prefix)
	if method == 0 {
		return ProtocolTCP
	}

	line := prefix
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = bytes.TrimSuffix(line[:i], []byte("\r"))
		if bytes.Contains(line[method:], []byte(" HTTP/")) {
			return ProtocolHTTP
		}
		return ProtocolTCP
	}

	if bytes.Contains(line[method:], []byte(" HTTP/")) {
		return ProtocolHTTP
	}
	// The request line is simply still in flight; trust the method token.
	return ProtocolHTTP
}

func matchMethod(prefix []byte) int {
	for _, m := range httpMethods {
		if bytes.HasPrefix(prefix, m) {
			return len(m)
		}
	}
	return 0
}

// Conn is a net.Conn whose first reads replay the bytes consumed by Peek.
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

// Peek reads the head of conn — up to maxBytes, bounded by timeout — and
// classifies it. For HTTP it keeps reading until the end of the header block so
// that rules can match on headers, and stops there: the body is never buffered.
//
// It never waits for maxBytes to arrive. Every peeked byte is replayed by the
// returned *Conn, so the tunnel stays byte-exact.
func Peek(conn net.Conn, maxBytes int, timeout time.Duration) (*Conn, Result, error) {
	if maxBytes <= 0 {
		return nil, Result{}, errors.New("inspector: maxBytes must be positive")
	}

	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, Result{}, err
		}
	}

	buf := make([]byte, 0, maxBytes)
	chunk := make([]byte, maxBytes)

	var (
		readErr  error
		proto    Protocol
		classed  bool
		complete bool
	)

	for len(buf) < maxBytes {
		n, err := conn.Read(chunk[:maxBytes-len(buf)])
		if n > 0 {
			buf = append(buf, chunk[:n]...)

			if !classed && bytes.IndexByte(buf, '\n') >= 0 {
				proto = Detect(buf)
				classed = true
				if proto != ProtocolHTTP {
					complete = true
					break
				}
			}
			// For HTTP, keep going until the header block ends.
			if classed && proto == ProtocolHTTP && hasHeaderEnd(buf) {
				complete = true
				break
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}

	// From here on the connection is a long-lived tunnel with no deadline.
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, Result{}, err
		}
	}

	if readErr != nil && len(buf) == 0 {
		if errors.Is(readErr, os.ErrDeadlineExceeded) {
			return nil, Result{}, errors.New("inspector: client sent no data before deadline")
		}
		if errors.Is(readErr, io.EOF) {
			return nil, Result{}, io.EOF
		}
		return nil, Result{}, readErr
	}

	if !classed {
		proto = Detect(buf)
	}

	res := Result{Protocol: proto}
	if proto == ProtocolHTTP {
		res.Request = parseRequest(buf, !complete)
	}

	return &Conn{Conn: conn, prefix: bytes.NewReader(buf)}, res, nil
}

func hasHeaderEnd(buf []byte) bool {
	for _, t := range headerTerminators {
		if bytes.Contains(buf, t) {
			return true
		}
	}
	return false
}

// parseRequest extracts routable fields from the buffered head.
//
// It parses a copy: the original bytes are replayed to the backend untouched.
// net/http does the heavy lifting when the header block is complete; otherwise
// only the request line is read, which is enough for method and path rules.
func parseRequest(buf []byte, partial bool) *Request {
	if !partial {
		if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf))); err == nil {
			return &Request{
				Method: req.Method,
				Path:   requestPath(req.RequestURI),
				Host:   hostOnly(req.Host),
				Header: req.Header,
			}
		}
		// Fall through: a malformed header block still has a usable first line.
	}

	r := &Request{Header: map[string][]string{}, Partial: true}

	line, rest, found := cutLine(buf)
	if !found && line == "" {
		return r
	}
	fields := strings.Fields(line)
	if len(fields) >= 1 {
		r.Method = fields[0]
	}
	if len(fields) >= 2 {
		r.Path = requestPath(fields[1])
	}

	// Best-effort header scan over whatever arrived.
	for found {
		var l string
		l, rest, found = cutLine(rest)
		if l == "" {
			break
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			break
		}
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		r.Header[name] = append(r.Header[name], value)
		if name == "Host" && r.Host == "" {
			r.Host = hostOnly(value)
		}
	}
	return r
}

func cutLine(b []byte) (line string, rest []byte, found bool) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return strings.TrimRight(string(b), "\r"), nil, false
	}
	return strings.TrimRight(string(b[:i]), "\r"), b[i+1:], true
}

// requestPath strips the query string and normalises an absolute-form target,
// so a rule can match "/api/x" whether the client sent the origin form or the
// absolute form used by proxies.
func requestPath(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	if i := strings.Index(target, "://"); i >= 0 {
		if j := strings.IndexByte(target[i+3:], '/'); j >= 0 {
			return target[i+3+j:]
		}
		return "/"
	}
	return target
}

// hostOnly drops the port, so rules match on the hostname alone.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
