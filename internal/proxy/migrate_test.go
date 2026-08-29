package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"watershed/internal/config"
)

// backendStub is a listener standing in for a node: it records what arrived, including the PROXY
// header, and can reply.
type backendStub struct {
	ln       net.Listener
	accepted chan *stubConn
}

type stubConn struct {
	conn     net.Conn
	mu       sync.Mutex
	received *bytes.Buffer
	done     chan struct{}
}

// bytes copies what has arrived so far; the reader goroutine keeps appending.
func (c *stubConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte{}, c.received.Bytes()...)
}

func (c *stubConn) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.received.Len()
}

func newBackendStub(t *testing.T) *backendStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &backendStub{ln: ln, accepted: make(chan *stubConn, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			sc := &stubConn{conn: c, received: &bytes.Buffer{}, done: make(chan struct{})}
			b.accepted <- sc
			go func() {
				defer close(sc.done)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						sc.mu.Lock()
						sc.received.Write(buf[:n])
						sc.mu.Unlock()
					}
					if err != nil {
						// What a node does on end-of-stream in handover mode: finish up and close,
						// which is the proxy's cue that the session was exported.
						c.Close()
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *backendStub) addr() string { return b.ln.Addr().String() }

func (b *backendStub) next(t *testing.T) *stubConn {
	t.Helper()
	select {
	case c := <-b.accepted:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("backend was never dialled")
		return nil
	}
}

// serverFor builds a Server whose TCP backend is the stub, with the PROXY header on so a resume key
// has somewhere to travel.
func serverFor(t *testing.T, addr string) *Server {
	t.Helper()
	be := config.Backend{Transport: config.TransportPlain, Addr: addr, SendProxy: true}
	cfg := &config.Config{
		MaxInspectBytes: 4096,
		InspectTimeout:  time.Second,
		DialTimeout:     2 * time.Second,
		TCPBackend:      be,
		HTTPBackend:     be,
		Backends:        map[string]config.Backend{config.DefaultTCPBackendName: be, config.DefaultHTTPBackendName: be},
	}
	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// runProxy serves one client connection through the server and returns the client end of the pipe.
func runProxy(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv.handle(c)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// resumeKey pulls the resume TLV out of a PROXY v2 header, or "" when there is none.
func resumeKey(header []byte) string {
	if len(header) < 16 {
		return ""
	}
	length := int(binary.BigEndian.Uint16(header[14:16]))
	body := header[16 : 16+length]
	// Skip the address block: 12 bytes for IPv4, 36 for IPv6.
	switch header[13] {
	case 0x11:
		body = body[12:]
	case 0x21:
		body = body[36:]
	default:
		// LOCAL: no addresses, TLVs start immediately.
	}
	for len(body) >= 3 {
		typ := body[0]
		n := int(binary.BigEndian.Uint16(body[1:3]))
		if len(body) < 3+n {
			return ""
		}
		if typ == 0xE0 {
			return string(body[3 : 3+n])
		}
		body = body[3+n:]
	}
	return ""
}

func TestMigrationMovesALiveConnectionWithoutDroppingTheClient(t *testing.T) {
	blue := newBackendStub(t)
	green := newBackendStub(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")

	client := runProxy(t, srv)
	// The proxy only dials a backend once it has classified the stream, so the client speaks first.
	if _, err := client.Write(frame(8)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	blueConn := blue.next(t)
	waitFor(t, "the first frame to reach blue", func() bool { return blueConn.size() >= 16+12+4+8 })

	srv.backends.Switch(green.addr(), "instance-green")
	res := srv.Migrate(10, 0, 3*time.Second)

	greenConn := green.next(t)
	waitFor(t, "green to see the PROXY header", func() bool { return greenConn.size() >= 16 })

	if res.Moved != 1 || res.Remaining != 0 {
		t.Fatalf("migrate result = %+v, want 1 moved and none left", res)
	}
	if key := resumeKey(greenConn.bytes()); key == "" {
		t.Fatal("green got no resume key, so it cannot tell a handover from a new client")
	} else if got, want := key[:len("instance-blue")], "instance-blue"; got != want {
		t.Fatalf("resume key names %q, want the instance the connection came from (%q)", got, want)
	}

	// Blue's socket was half-closed, which is the node's cue to export.
	waitFor(t, "blue to see end-of-stream", func() bool {
		select {
		case <-blueConn.done:
			return true
		default:
			return false
		}
	})

	// The client never noticed: it can still send, and the bytes now land on green.
	if _, err := client.Write(frame(5)); err != nil {
		t.Fatalf("client write after migration: %v", err)
	}
	waitFor(t, "the next frame to reach green", func() bool { return greenConn.size() >= 16+4+5 })
}

// A frame in flight when the move is asked for finishes on the old backend; whatever follows it in
// the same read belongs to the new one and is carried across. This is the case that decides whether
// a handover is safe at all: hand either backend half a frame and it reads the next four bytes as a
// length, gets nonsense, and drops the client.
func TestAFrameInFlightFinishesOnTheOldBackendAndTheNextIsCarried(t *testing.T) {
	blue := newBackendStub(t)
	green := newBackendStub(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")

	client := runProxy(t, srv)
	first := frame(4)
	inFlight := frame(64)
	after := frame(16)

	// A whole frame plus the head of the next: the proxy is now mid-frame.
	if _, err := client.Write(append(append([]byte{}, first...), inFlight[:10]...)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	blueConn := blue.next(t)
	waitFor(t, "blue to get the first frame and the head of the second", func() bool {
		return blueConn.size() >= 16+12+len(first)+10
	})

	// Ask to move while that frame is still open, then let the client finish it and start another.
	srv.backends.Switch(green.addr(), "instance-green")
	pending := srv.sessions.stale(srv.backends.Current().Generation)
	if len(pending) != 1 {
		t.Fatalf("expected one session on the old backend, got %d", len(pending))
	}
	sess := pending[0]
	go srv.Migrate(10, 0, 5*time.Second)
	// The client's next write must land AFTER the session knows it is moving, or the boundary is
	// crossed before anything is pending and there is nothing to carry.
	waitFor(t, "the session to be asked to move", func() bool { return sess.migrateWanted.Load() })
	// The rest of the open frame, plus the head of the one after it: the boundary falls in the
	// middle of this write, and everything past it must travel to green.
	if _, err := client.Write(append(append([]byte{}, inFlight[10:]...), after[:8]...)); err != nil {
		t.Fatalf("client write rest: %v", err)
	}

	greenConn := green.next(t)
	waitFor(t, "blue's stream to end", func() bool {
		select {
		case <-blueConn.done:
			return true
		default:
			return false
		}
	})

	// Blue got both complete frames and nothing of the third.
	const headerLen = 16 + 12 // signature block + IPv4 addresses
	bluePayload := blueConn.bytes()[headerLen:]
	wantBlue := append(append([]byte{}, first...), inFlight...)
	if !bytes.Equal(bluePayload, wantBlue) {
		t.Fatalf("blue received %d payload bytes, want %d — the frame in flight must finish where it started",
			len(bluePayload), len(wantBlue))
	}

	// Green gets the carried head first, then the rest of that same frame — reassembled across the
	// move, which is the only way the frame stays whole for whoever parses it.
	if _, err := client.Write(after[8:]); err != nil {
		t.Fatalf("client write tail: %v", err)
	}
	waitFor(t, "green to receive the frame that was split across the move", func() bool {
		return bytes.Contains(greenConn.bytes(), after)
	})
}

// A client that goes quiet in the middle of a frame cannot be moved: the session stays where it is
// and the caller is told, rather than the proxy splitting a frame across two backends.
func TestASessionStuckMidFrameStaysPut(t *testing.T) {
	blue := newBackendStub(t)
	green := newBackendStub(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")

	client := runProxy(t, srv)
	half := frame(64)[:10] // a length and part of a payload, then silence
	if _, err := client.Write(half); err != nil {
		t.Fatalf("client write: %v", err)
	}
	blueConn := blue.next(t)
	waitFor(t, "blue to get the fragment", func() bool { return blueConn.size() >= 16+12+len(half) })

	srv.backends.Switch(green.addr(), "instance-green")
	res := srv.Migrate(10, 0, frameWait+2*time.Second)

	if res.Moved != 0 || res.Remaining != 1 {
		t.Fatalf("migrate result = %+v, want nothing moved and one left behind", res)
	}
	select {
	case <-green.accepted:
		t.Fatal("green must not be dialled for a session that could not reach a frame boundary")
	default:
	}
}

func TestMigrateIsANoOpWhenNothingIsStale(t *testing.T) {
	blue := newBackendStub(t)
	srv := serverFor(t, blue.addr())

	res := srv.Migrate(10, 0, time.Second)

	if res.Considered != 0 || res.Moved != 0 {
		t.Fatalf("migrate on an idle proxy = %+v, want zeros", res)
	}
}

func TestNewConnectionsGoToTheCurrentBackend(t *testing.T) {
	blue := newBackendStub(t)
	green := newBackendStub(t)
	srv := serverFor(t, blue.addr())

	srv.backends.Switch(green.addr(), "instance-green")
	client := runProxy(t, srv)
	if _, err := client.Write(frame(2)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	greenConn := green.next(t)
	waitFor(t, "green to receive the frame", func() bool { return greenConn.size() >= 16+12+4+2 })
	select {
	case <-blue.accepted:
		t.Fatal("a connection opened after the switch must not reach the old backend")
	default:
	}
}
