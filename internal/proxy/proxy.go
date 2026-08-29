// Package proxy wires the listener, the inspector and the backend dialer into
// a TLS-terminating TCP proxy.
package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"watershed/internal/backend"
	"watershed/internal/config"
	"watershed/internal/dialer"
	"watershed/internal/inspector"
	"watershed/internal/metrics"
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

	// backends holds the current TCP target, which a rolling update replaces at runtime; sessions
	// tracks the connections that can be moved when it does.
	backends *backend.Holder
	sessions *registry
	// migrationFailures counts clients dropped because their new backend could not be dialled.
	migrationFailures atomic.Uint64

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
		cfg:      cfg,
		log:      logger,
		router:   rt,
		backends: backend.NewHolder(cfg.TCPBackend, ""),
		sessions: newRegistry(),
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Backends exposes the current-target holder so the admin API can point the proxy elsewhere.
func (s *Server) Backends() *backend.Holder { return s.backends }

// MigratableSessions is how many live connections could be moved to a new backend.
func (s *Server) MigratableSessions() int { return s.sessions.size() }

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

	metrics.ConnectionOpened()
	defer metrics.ConnectionClosed()

	inspectStart := time.Now()
	peeked, res, err := inspector.Peek(client, s.cfg.MaxInspectBytes, s.cfg.InspectTimeout)
	if err != nil {
		metrics.InspectFailed()
		if !errors.Is(err, io.EOF) {
			s.log.Printf("inspect %s: %v", client.RemoteAddr(), err)
		}
		return
	}
	metrics.Inspected(time.Since(inspectStart))

	name, target, migratable := s.pick(res)

	upstream, err := dialer.Dial(target.Backend, s.cfg.DialTimeout, client.RemoteAddr(), client.LocalAddr())
	if err != nil {
		metrics.DialFailed()
		s.log.Printf("route %s -> %s (%s): %v", client.RemoteAddr(), name, res.Protocol, err)
		return
	}
	defer upstream.Close()
	metrics.Routed(res.Protocol.String())

	s.log.Printf("route %s -> %s %s (%s/%s)",
		client.RemoteAddr(), name, target.Backend.Addr, res.Protocol, target.Backend.Transport)

	if !migratable {
		// An HTTP connection to the decoy: short, stateless, and nothing a rollout needs to carry.
		Splice(peeked, upstream)
		return
	}

	sess := &session{
		client:   peeked,
		upstream: upstream,
		cfg:      s.cfg,
		holder:   s.backends,
		log:      s.log,
		connID:   s.sessions.nextConnID(),
		target:   target,
		failures: &s.migrationFailures,
	}
	sess.generation.Store(target.Generation)
	s.sessions.add(sess)
	defer s.sessions.remove(sess.connID)
	sess.run()
	// The session may have moved to another backend; close whatever it ended on. The deferred
	// close above still covers the one dialled here.
	if sess.upstream != upstream {
		_ = sess.upstream.Close()
	}
}

// pick resolves a peek result to a named backend, and says whether the connection can be migrated.
//
// Non-HTTP always goes to the TCP backend: rules describe HTTP requests and
// have nothing to match against a raw stream. For HTTP the rules decide, and
// the HTTP backend is the fallback when none applies.
//
// Only the TCP backend is migratable, and it is read from the holder rather than the config: that
// is the address a rolling update replaces, and reading it per connection is what makes new
// connections land on the new instance the moment the switch happens.
func (s *Server) pick(res inspector.Result) (string, *backend.Target, bool) {
	if res.Protocol != inspector.ProtocolHTTP || res.Request == nil {
		return config.DefaultTCPBackendName, s.backends.Current(), true
	}

	req := router.Request{
		Method: res.Request.Method,
		Path:   res.Request.Path,
		Host:   res.Request.Host,
		Header: res.Request.Header,
	}
	if name, ok := s.router.Match(req); ok {
		if b, exists := s.cfg.Backends[name]; exists {
			return name, &backend.Target{Backend: b}, false
		}
		// New() rejects unknown backends, so this is unreachable in practice;
		// falling back beats dropping the connection if it ever happens.
		s.log.Printf("rule matched unknown backend %q, using the default", name)
	}
	return config.DefaultHTTPBackendName, &backend.Target{Backend: s.cfg.HTTPBackend}, false
}

// Splice copies bytes in both directions until either side finishes, then
// closes both. It is exported so tests can exercise it directly.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// a is the client side, b the backend: this half carries the client's bytes upstream.
		metrics.Upstream(copyThenHalfClose(b, a))
	}()
	go func() {
		defer wg.Done()
		metrics.Downstream(copyThenHalfClose(a, b))
	}()
	wg.Wait()
}

// copyThenHalfClose streams src into dst and signals end-of-stream to dst.
// If dst cannot half-close it is closed outright, which unblocks the peer
// goroutine instead of leaking it.
func copyThenHalfClose(dst, src net.Conn) int64 {
	n, _ := io.Copy(dst, src)

	if hc, ok := dst.(halfCloser); ok {
		_ = hc.CloseWrite()
		return n
	}
	// inspector.Conn wraps the real connection; unwrap one level before giving up.
	if ic, ok := dst.(*inspector.Conn); ok {
		if hc, ok := ic.Conn.(halfCloser); ok {
			_ = hc.CloseWrite()
			return n
		}
	}
	_ = dst.Close()
	return n
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

// StaleSessions is how many live connections are still on a backend older than the current one —
// what a migration would move.
func (s *Server) StaleSessions() int {
	return len(s.sessions.stale(s.backends.Current().Generation))
}
