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
	cfg *config.Config
	log *log.Logger

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool

	wg sync.WaitGroup
}

// New returns a Server. A nil logger discards output.
func New(cfg *config.Config, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		cfg:   cfg,
		log:   logger,
		conns: make(map[net.Conn]struct{}),
	}
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

	peeked, proto, err := inspector.Peek(client, s.cfg.MaxInspectBytes, s.cfg.InspectTimeout)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.log.Printf("inspect %s: %v", client.RemoteAddr(), err)
		}
		return
	}

	backend := s.cfg.TCPBackend
	if proto == inspector.ProtocolHTTP {
		backend = s.cfg.HTTPBackend
	}

	upstream, err := dialer.Dial(backend, s.cfg.DialTimeout)
	if err != nil {
		s.log.Printf("route %s -> %s (%s): %v", client.RemoteAddr(), backend.Addr, proto, err)
		return
	}
	defer upstream.Close()

	s.log.Printf("route %s -> %s (%s/%s)", client.RemoteAddr(), backend.Addr, proto, backend.Transport)
	Splice(peeked, upstream)
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
