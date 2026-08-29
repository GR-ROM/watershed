package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"watershed/internal/backend"
	"watershed/internal/config"
	"watershed/internal/dialer"
	"watershed/internal/metrics"
	"watershed/internal/proxyproto"
)

// frameWait bounds how long a migration waits for the client to finish the frame it is in the
// middle of. A frame is a few kilobytes on a live connection, so this is generous; when it expires
// the session simply stays where it is, because moving it would hand the new backend half a frame.
// A var, not a const, only so a test can shorten it; nothing reassigns it at runtime.
var frameWait = 2 * time.Second

// exportWait bounds how long the proxy waits for the backend to close after being told there are no
// more client bytes. A node in handover mode exports the session and closes; one that does not is
// either not in handover mode or is stuck, and either way the connection must not hang here — the
// client is waiting on the other end of it.
// A var for the same reason as frameWait above.
var exportWait = 10 * time.Second

// session is one client connection spliced to a backend, with the ability to change backends
// underneath the client.
//
// The move works because of what each side can promise. Only this proxy can stop the
// client→backend direction at a safe place, so it does: it stops on a frame boundary and
// half-closes the backend socket. The node reads that end-of-stream as "no more client bytes are
// coming", exports the session and closes — so everything it still owed the client arrives before
// the socket goes away, and nothing arrives after. Only then is the new instance dialled, with a
// resume key in the PROXY header. The client sees a pause, not a disconnect: its own TLS session to
// this proxy is never touched.
type session struct {
	client   net.Conn // already includes the peeked prefix (inspector.Conn)
	upstream net.Conn

	cfg    *config.Config
	holder *backend.Holder
	log    *log.Logger

	// connID is this proxy's id for the connection, echoed in the resume key so the node can match
	// its exported record to the socket that comes back.
	connID uint64

	// target is the backend the upstream is dialled to. Read by the registry from another
	// goroutine, so its generation is published separately as an atomic.
	target     *backend.Target
	generation atomic.Uint64

	cursor frameCursor

	// migrateWanted asks the upstream copier to stop at the next frame boundary. A blocking read is
	// interrupted with a read deadline, which is the only way to make a goroutine parked in Read
	// notice anything at all.
	migrateWanted atomic.Bool
	// carried holds bytes read from the client after the boundary — they belong to the next backend
	// and are written there first.
	carried []byte

	// failures counts moves that ended with the client dropped. Kept on the server rather than
	// here, because by the time a rollout is counted this session is already out of the registry.
	failures *atomic.Uint64
}

// Migrate asks this session to move to the current backend at the next frame boundary. It returns
// immediately; the move happens on the session's own goroutine.
func (s *session) Migrate() {
	if s.migrateWanted.CompareAndSwap(false, true) {
		// Wake the copier out of its blocking read. It re-arms or clears the deadline itself.
		_ = s.client.SetReadDeadline(time.Now())
	}
}

// run splices both directions until the client or the backend finishes, moving between backends as
// asked in between.
func (s *session) run() {
	for s.spliceUntilMigrationOrEnd() {
	}
}

// spliceUntilMigrationOrEnd runs one backend's worth of splicing. It returns true when the session
// moved to another backend and should keep going, false when the connection is finished.
//
// The two directions are deliberately asymmetric. Downstream (backend→client) is a plain copy that
// ends when the backend closes — after a half-close that is the node saying "exported, nothing
// left". Upstream (client→backend) is the one that counts frames, because it is the direction that
// has to stop somewhere safe.
func (s *session) spliceUntilMigrationOrEnd() bool {
	downstreamDone := make(chan struct{})
	upstreamDone := make(chan bool, 1)

	go func() {
		defer close(downstreamDone)
		metrics.Downstream(copyThenHalfClose(s.client, s.upstream))
	}()
	go func() { upstreamDone <- s.copyUpstream() }()

	if moved := <-upstreamDone; !moved {
		<-downstreamDone
		return false // ordinary end of life: the client or the backend closed
	}

	// The backend was told there are no more client bytes. Everything it still owes the client
	// arrives now, and it closes when it is done — that close is what says "exported". Bounded,
	// because a backend that never closes would otherwise hold the client here forever.
	select {
	case <-downstreamDone:
	case <-time.After(exportWait):
		s.log.Printf("migrate %s: backend %s did not close %s after end-of-stream, forcing",
			s.client.RemoteAddr(), s.target.Backend.Addr, exportWait)
		_ = s.upstream.Close()
		<-downstreamDone
	}

	if err := s.redial(); err != nil {
		s.log.Printf("migrate %s: %v — dropping the connection", s.client.RemoteAddr(), err)
		metrics.MigrationFailed()
		if s.failures != nil {
			s.failures.Add(1)
		}
		return false
	}
	metrics.Migrated()
	s.log.Printf("migrated %s -> %s (instance %s)", s.client.RemoteAddr(), s.target.Backend.Addr, s.target.InstanceID)
	return true
}

// copyUpstream streams the client into the backend, counting frames. It returns true when it
// stopped on a frame boundary because a migration was asked for, and false when the stream ended.
func (s *session) copyUpstream() bool {
	buf := make([]byte, 32*1024)
	var total int64
	defer func() { metrics.Upstream(total) }()

	// Bytes carried over from the previous backend go first: they were read from the client but
	// deliberately not delivered to the instance that was going away.
	if len(s.carried) > 0 {
		if _, err := s.upstream.Write(s.carried); err != nil {
			return false
		}
		total += int64(len(s.carried))
		s.carried = nil
	}

	// waitingForFrameEnd is true once a migration has been asked for while a frame was in flight:
	// the client is given frameWait to finish it, and the session stays put if it does not.
	waitingForFrameEnd := false

	for {
		if s.migrateWanted.Load() && s.cursor.atBoundary() {
			s.clearDeadline()
			s.halfCloseUpstream()
			return true
		}

		n, err := s.client.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			lastBoundary := s.cursor.advance(chunk)

			if s.migrateWanted.Load() && lastBoundary > 0 {
				if _, werr := s.upstream.Write(chunk[:lastBoundary]); werr != nil {
					return false
				}
				total += int64(lastBoundary)
				if lastBoundary < n {
					// The rest belongs to a frame that will finish on the new backend. The cursor
					// already counted it and travels with the session, so the two stay in step.
					s.carried = append(s.carried[:0], chunk[lastBoundary:]...)
				}
				s.clearDeadline()
				s.halfCloseUpstream()
				return true
			}

			if _, werr := s.upstream.Write(chunk); werr != nil {
				return false
			}
			total += int64(n)
		}

		if err != nil {
			if os.IsTimeout(err) {
				if !s.migrateWanted.Load() {
					s.clearDeadline() // a stray deadline from a migration that already resolved
					continue
				}
				if s.cursor.atBoundary() {
					s.clearDeadline()
					s.halfCloseUpstream()
					return true
				}
				if !waitingForFrameEnd {
					waitingForFrameEnd = true
					_ = s.client.SetReadDeadline(time.Now().Add(frameWait))
					continue
				}
				// The client stopped mid-frame. Leave the session where it is rather than hand the
				// new backend a fragment; the caller sees it as "not moved".
				s.log.Printf("migrate %s: client idle mid-frame, staying on %s",
					s.client.RemoteAddr(), s.target.Backend.Addr)
				s.migrateWanted.Store(false)
				waitingForFrameEnd = false
				s.clearDeadline()
				continue
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Printf("upstream copy %s: %v", s.client.RemoteAddr(), err)
			}
			s.halfCloseUpstream()
			return false
		}
	}
}

func (s *session) clearDeadline() {
	_ = s.client.SetReadDeadline(time.Time{})
}

// halfCloseUpstream tells the backend "no more client bytes". For a node in handover mode that is
// the signal to export this session; for an ordinary end of stream it is the normal shutdown.
func (s *session) halfCloseUpstream() {
	if hc, ok := s.upstream.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = s.upstream.Close()
}

// redial opens the connection to the current backend, announcing the client and the resume key.
func (s *session) redial() error {
	_ = s.upstream.Close()

	next := s.holder.Current()
	conn, err := dialer.DialResuming(next.Backend, s.cfg.DialTimeout, s.client.RemoteAddr(), s.client.LocalAddr(),
		proxyproto.ResumeTLV(s.target.InstanceID, s.connID))
	if err != nil {
		return err
	}

	s.upstream = conn
	s.target = next
	s.generation.Store(next.Generation)
	s.migrateWanted.Store(false) // ready to be moved again by a later rollout
	return nil
}

// registry holds the sessions that can be moved — the ones on the TCP backend. HTTP connections to
// the decoy are not tracked: they are short, stateless and not worth carrying across a rollout.
type registry struct {
	mu       sync.Mutex
	sessions map[uint64]*session
	nextID   uint64
}

func newRegistry() *registry {
	return &registry{sessions: make(map[uint64]*session)}
}

func (r *registry) add(s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.connID] = s
}

func (r *registry) remove(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}

func (r *registry) nextConnID() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	return r.nextID
}

// stale returns the sessions whose backend is older than the given generation.
func (r *registry) stale(generation uint64) []*session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*session
	for _, s := range r.sessions {
		if s.generation.Load() < generation {
			out = append(out, s)
		}
	}
	return out
}

func (r *registry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// MigrateResult reports what one migration pass achieved. Remaining is the number still on an old
// backend — sessions whose client went quiet mid-frame, or whose new backend could not be dialled.
type MigrateResult struct {
	Considered int
	Moved      int
	Remaining  int
	// Failed counts sessions whose new backend could not be dialled: the client was dropped and
	// will reconnect. Counted separately because such a session leaves the registry, so it would
	// otherwise be indistinguishable from one that moved — and a rollout that cut connections must
	// not report itself as clean.
	Failed int
}

// Migrate moves every session still on an older backend to the current one, in batches, and waits
// for them to land or for the deadline.
//
// Batched because each move costs the node an export and the client a pause; a hundred at once
// would be a hundred simultaneous exports on a node that is also still serving traffic.
func (s *Server) Migrate(batch int, interval, timeout time.Duration) MigrateResult {
	current := s.backends.Current()
	pending := s.sessions.stale(current.Generation)
	res := MigrateResult{Considered: len(pending)}
	if len(pending) == 0 {
		return res
	}
	if batch <= 0 {
		batch = len(pending)
	}

	failuresBefore := s.migrationFailures.Load()
	deadline := time.Now().Add(timeout)
	for i := 0; i < len(pending); i += batch {
		end := i + batch
		if end > len(pending) {
			end = len(pending)
		}
		for _, sess := range pending[i:end] {
			sess.Migrate()
		}
		if end < len(pending) && interval > 0 {
			time.Sleep(interval)
		}
		if time.Now().After(deadline) {
			break
		}
	}

	for time.Now().Before(deadline) {
		if len(s.sessions.stale(current.Generation)) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	res.Remaining = len(s.sessions.stale(current.Generation))
	res.Failed = int(s.migrationFailures.Load() - failuresBefore)
	res.Moved = res.Considered - res.Remaining - res.Failed
	if res.Moved < 0 {
		res.Moved = 0 // a failure from an earlier pass landing in this window
	}
	return res
}
