// Package proxy wires the listener, the inspector and the backend dialer into
// a TLS-terminating TCP proxy.
package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"watershed/internal/config"
	"watershed/internal/dialer"
	"watershed/internal/inspector"
	"watershed/internal/router"
)

// halfCloser is implemented by *net.TCPConn and *tls.Conn. Using it lets the
// proxy forward a one-way shutdown instead of tearing the whole tunnel down,
// which matters for protocols where the client signals "no more input" by
// closing its write side.
type halfCloser interface {
	CloseWrite() error
}

// Server proxies accepted connections to the configured backends.
type Server struct {
	cfg    *config.Config
	log    *log.Logger
	router *router.Router

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool

	wg sync.WaitGroup
}

// New returns a Server. A nil logger discards output.
//
// It fails when the rule set is invalid — an unknown backend or a malformed
// pattern is a configuration error, and it must surface at startup rather than
// on the first request that happens to hit the broken rule.
func New(cfg *config.Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	rt, err := router.New(cfg.Rules, func(name string) bool {
		_, ok := cfg.Backends[name]
		return ok
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:    cfg,
		log:    logger,
		router: rt,
		conns:  make(map[net.Conn]struct{}),
	}, nil
}

// Serve accepts connections until ln is closed. It always returns a non-nil
// error; after Shutdown that error is net.ErrClosed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosing() || errors.Is(err, net.ErrClosed) {
				return net.ErrClosed
			}
			// A single failed handshake or dropped SYN must not kill the loop.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}

		s.track(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(conn)
			s.handle(conn)
		}()
	}
}

// handle inspects one client connection and splices it to a backend.
func (s *Server) handle(client net.Conn) {
	defer client.Close()

	peeked, res, err := inspector.Peek(client, s.cfg.MaxInspectBytes, s.cfg.InspectTimeout)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.log.Printf("inspect %s: %v", client.RemoteAddr(), err)
		}
		return
	}

	name, backend := s.pick(res)

	upstream, err := dialer.Dial(backend, s.cfg.DialTimeout)
	if err != nil {
		s.log.Printf("route %s -> %s (%s): %v", client.RemoteAddr(), name, res.Protocol, err)
		return
	}
	defer upstream.Close()

	s.log.Printf("route %s -> %s %s (%s/%s)",
		client.RemoteAddr(), name, backend.Addr, res.Protocol, backend.Transport)
	Splice(peeked, upstream)
}

// pick resolves a peek result to a named backend.
//
// Non-HTTP always goes to the TCP backend: rules describe HTTP requests and
// have nothing to match against a raw stream. For HTTP the rules decide, and
// the HTTP backend is the fallback when none applies.
func (s *Server) pick(res inspector.Result) (string, config.Backend) {
	if res.Protocol != inspector.ProtocolHTTP || res.Request == nil {
		return config.DefaultTCPBackendName, s.cfg.TCPBackend
	}

	req := router.Request{
		Method: res.Request.Method,
		Path:   res.Request.Path,
		Host:   res.Request.Host,
		Header: res.Request.Header,
	}
	if name, ok := s.router.Match(req); ok {
		if b, exists := s.cfg.Backends[name]; exists {
			return name, b
		}
		// New() rejects unknown backends, so this is unreachable in practice;
		// falling back beats dropping the connection if it ever happens.
		s.log.Printf("rule matched unknown backend %q, using the default", name)
	}
	return config.DefaultHTTPBackendName, s.cfg.HTTPBackend
}

// Splice copies bytes in both directions until either side finishes, then
// closes both. It is exported so tests can exercise it directly.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyThenHalfClose(b, a)
	}()
	go func() {
		defer wg.Done()
		copyThenHalfClose(a, b)
	}()
	wg.Wait()
}

// copyThenHalfClose streams src into dst and signals end-of-stream to dst.
// If dst cannot half-close it is closed outright, which unblocks the peer
// goroutine instead of leaking it.
func copyThenHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)

	if hc, ok := dst.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	// inspector.Conn wraps the real connection; unwrap one level before giving up.
	if ic, ok := dst.(*inspector.Conn); ok {
		if hc, ok := ic.Conn.(halfCloser); ok {
			_ = hc.CloseWrite()
			return
		}
	}
	_ = dst.Close()
}

// Shutdown stops accepting, closes live connections and waits for the handlers
// to finish or for ctx-like timeout to elapse.
func (s *Server) Shutdown(timeout time.Duration) {
	s.mu.Lock()
	s.closing = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		s.log.Printf("shutdown: timed out after %s with handlers still running", timeout)
	}
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}
