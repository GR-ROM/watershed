package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// The registry is what an operator's "how far along is the rollout" question is answered from, and
// what Migrate walks. Miscounting it means either declaring a rollout finished while clients are
// still on the old instance, or never declaring it finished at all.
func TestRegistryCountsWhatIsStillMovable(t *testing.T) {
	r := newRegistry()
	if r.size() != 0 {
		t.Fatalf("a fresh registry holds %d sessions, want 0", r.size())
	}

	first, second := &session{}, &session{}
	first.generation.Store(1)
	second.generation.Store(2)

	idA, idB := r.nextConnID(), r.nextConnID()
	if idA == idB {
		t.Fatal("two sessions must not share a connection id — it is half of the resume key")
	}
	first.connID, second.connID = idA, idB
	r.add(first)
	r.add(second)
	if r.size() != 2 {
		t.Fatalf("size = %d, want 2", r.size())
	}

	// Stale means "on a backend older than the current one" — those are the ones left to move.
	if got := len(r.stale(2)); got != 1 {
		t.Fatalf("%d session(s) behind generation 2, want 1", got)
	}
	if got := len(r.stale(3)); got != 2 {
		t.Fatalf("%d session(s) behind generation 3, want 2", got)
	}
	if got := len(r.stale(1)); got != 0 {
		t.Fatalf("%d session(s) behind generation 1, want 0", got)
	}

	r.remove(idA)
	if r.size() != 1 {
		t.Fatalf("size after remove = %d, want 1", r.size())
	}
	r.remove(idA) // removing what is already gone is not an error
	if r.size() != 1 {
		t.Fatalf("a repeated remove changed the size to %d", r.size())
	}
}

// The export signal is a half-close. An upstream that cannot half-close (anything that is not a TCP
// connection) must still be told the client is done, or the session would hang waiting for a node
// that was never asked to export.
func TestHalfCloseFallsBackToClosingTheUpstream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &session{upstream: client}
	s.halfCloseUpstream()

	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the other end must see the connection finish")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream was neither half-closed nor closed")
	}
}

// A backend that takes the half-close and then never closes is either not in handover mode or is
// stuck. Either way the client is waiting on the other end of this connection, so the wait is
// bounded and the socket is taken away — the session still moves.
func TestABackendThatNeverClosesIsForcedAfterTheExportWait(t *testing.T) {
	originalExportWait := exportWait
	exportWait = 250 * time.Millisecond
	t.Cleanup(func() { exportWait = originalExportWait })

	stuck := newSilentBackend(t)
	green := newBackendStub(t)
	srv := serverFor(t, stuck.addr())
	srv.backends.Switch(stuck.addr(), "instance-stuck")

	client := runProxy(t, srv)
	if _, err := client.Write(frame(32)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	waitFor(t, "the stuck backend to get the frame", func() bool { return stuck.size() >= 16+12+4+32 })

	srv.backends.Switch(green.addr(), "instance-green")
	start := time.Now()
	res := srv.Migrate(10, 0, 5*time.Second)

	if res.Moved != 1 {
		t.Fatalf("migrate result = %+v, want the session moved anyway", res)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the export wait was not bounded: took %s", elapsed)
	}
	greenConn := green.next(t)
	if greenConn == nil {
		t.Fatal("green was never dialled")
	}
}

// silentBackend accepts, reads for ever and never closes — not even on end-of-stream.
type silentBackend struct {
	ln       net.Listener
	mu       sync.Mutex
	received bytes.Buffer
}

func newSilentBackend(t *testing.T) *silentBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &silentBackend{ln: ln}
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			held <- c
			go func() {
				buf := make([]byte, 4096)
				for {
					n, readErr := c.Read(buf)
					if n > 0 {
						b.mu.Lock()
						b.received.Write(buf[:n])
						b.mu.Unlock()
					}
					if readErr != nil {
						// Deliberately not closing: this is the failure this test is about.
						if readErr != io.EOF {
							return
						}
						<-time.After(30 * time.Second)
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		close(held)
		for c := range held {
			c.Close()
		}
	})
	return b
}

func (b *silentBackend) addr() string { return b.ln.Addr().String() }

func (b *silentBackend) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.received.Len()
}

// A backend the config parser rejected must not be dialled by a migration either — the session
// stays where it is rather than being dropped on a target that cannot work.
func TestAMigrationToAnUndialableBackendLeavesTheSessionPut(t *testing.T) {
	blue := newBackendStub(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")

	client := runProxy(t, srv)
	if _, err := client.Write(frame(32)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	blueConn := blue.next(t)
	waitFor(t, "blue to get the frame", func() bool { return blueConn.size() >= 16+12+4+32 })

	// Nothing listens here.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	srv.backends.Switch(deadAddr, "instance-gone")
	res := srv.Migrate(10, 0, 3*time.Second)

	if res.Moved != 0 || res.Failed != 1 {
		t.Fatalf("migrate result = %+v, want the drop counted as a failure, not as a move", res)
	}
}

// Batching is what keeps a rollout from asking a node for a hundred simultaneous exports while it
// is still serving traffic. Zero means "all at once", and an expired deadline stops the pass rather
// than running it to the end regardless.
func TestMigrateBatchingAndDeadline(t *testing.T) {
	blue := newBackendStub(t)
	green := newBackendStub(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")

	var clients []net.Conn
	for i := 0; i < 3; i++ {
		c := runProxy(t, srv)
		if _, err := c.Write(frame(16)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		clients = append(clients, c)
	}
	for range clients {
		conn := blue.next(t)
		waitFor(t, "blue to get the frame", func() bool { return conn.size() >= 16+12+4+16 })
	}

	// A deadline that has already passed stops the pass after the first batch — the batch is
	// always dispatched, so at most one of the three is asked to move and the rest stay put.
	srv.backends.Switch(green.addr(), "instance-green")
	if res := srv.Migrate(1, time.Millisecond, 0); res.Considered != 3 || res.Moved > 1 {
		t.Fatalf("migrate with no time left = %+v, want 3 considered and at most one moved", res)
	}

	// batch = 0 means whatever is left, in one go.
	res := srv.Migrate(0, 0, 5*time.Second)
	if res.Moved != res.Considered || res.Failed != 0 || res.Remaining != 0 {
		t.Fatalf("migrate result = %+v, want everything still behind to move", res)
	}

	// And a pass with nothing left to do is cheap and honest.
	if again := srv.Migrate(10, 0, time.Second); again.Considered != 0 || again.Moved != 0 {
		t.Fatalf("a second pass = %+v, want nothing considered", again)
	}
}
