package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// What a client actually feels when its node is replaced underneath it.
//
// The other migration tests prove the session moves and nothing is lost. This one measures the
// pause: a client sends a numbered frame every few milliseconds and reads each one echoed back,
// and the migration happens in the middle. The gap between two consecutive echoes across the switch
// is the whole cost of the handover as far as the client is concerned — everything else about the
// rollout happens beside it, not to it.
//
// It also proves the two properties that make the number meaningful: every frame comes back, and
// they come back in order. A fast switch that dropped or reordered a frame would not be a fast
// switch, it would be a broken tunnel.
func TestSwitchingBackendsIsBarelyVisibleToTheClient(t *testing.T) {
	const (
		frames   = 60
		sendGap  = 5 * time.Millisecond
		payload  = 64
		migrateA = 25 // migrate once this many have been echoed
	)

	blue := newEchoBackend(t)
	green := newEchoBackend(t)
	srv := serverFor(t, blue.addr())
	srv.backends.Switch(blue.addr(), "instance-blue")
	client := runProxy(t, srv)

	type arrival struct {
		seq  int
		when time.Time
	}
	arrivals := make(chan arrival, frames)
	readerDone := make(chan struct{})
	// Counted here rather than by the channel's length: the collector drains it as fast as the
	// reader fills it, so len(arrivals) hovers at zero and a migration waiting on it fires after the
	// stream has ended — measuring nothing at all.
	var echoed atomic.Int32

	// Reader: pull whole frames off the socket and note when each landed.
	go func() {
		defer close(readerDone)
		header := make([]byte, 4)
		for i := 0; i < frames; i++ {
			if _, err := io.ReadFull(client, header); err != nil {
				return
			}
			body := make([]byte, int(binary.BigEndian.Uint32(header))-4)
			if _, err := io.ReadFull(client, body); err != nil {
				return
			}
			arrivals <- arrival{seq: int(binary.BigEndian.Uint32(body[:4])), when: time.Now()}
			echoed.Add(1)
		}
	}()

	// Sender: a numbered frame every sendGap, so the steady-state spacing is known.
	go func() {
		for i := 0; i < frames; i++ {
			f := frame(payload)
			binary.BigEndian.PutUint32(f[4:8], uint32(i))
			if _, err := client.Write(f); err != nil {
				return
			}
			time.Sleep(sendGap)
		}
	}()

	// Migrate once the stream is clearly flowing, from a goroutine so the client keeps sending
	// across the switch — a migration measured on an idle connection measures nothing.
	var res MigrateResult
	var startedAt, finishedAt time.Time
	migrated := make(chan struct{})
	go func() {
		defer close(migrated)
		for i := 0; i < 200 && echoed.Load() < migrateA; i++ {
			time.Sleep(time.Millisecond)
		}
		srv.backends.Switch(green.addr(), "instance-green")
		startedAt = time.Now()
		res = srv.Migrate(0, 0, 10*time.Second)
		finishedAt = time.Now()
	}()

	deadline := time.After(30 * time.Second)
	seen := make([]arrival, 0, frames)
collect:
	for len(seen) < frames {
		select {
		case a := <-arrivals:
			seen = append(seen, a)
		case <-readerDone:
			for len(arrivals) > 0 {
				seen = append(seen, <-arrivals)
			}
			break collect
		case <-deadline:
			break collect
		}
	}
	<-migrated

	if res.Moved != 1 {
		t.Fatalf("migrate result = %+v, want the session moved", res)
	}
	if len(seen) != frames {
		t.Fatalf("%d of %d frames came back — a switch that loses a frame is not a switch", len(seen), frames)
	}
	for i, a := range seen {
		if a.seq != i {
			t.Fatalf("frame %d arrived at position %d: the switch reordered the stream", a.seq, i)
		}
	}

	// The gap that actually contains the switch, rather than the largest gap anywhere: on an
	// unloaded machine the two are usually different, and reporting the maximum would credit the
	// migration with whatever the scheduler did somewhere else in the run.
	gaps := make([]time.Duration, 0, len(seen))
	var across time.Duration
	acrossAt := -1
	for i := 1; i < len(seen); i++ {
		gap := seen[i].when.Sub(seen[i-1].when)
		gaps = append(gaps, gap)
		if seen[i-1].when.Before(finishedAt) && seen[i].when.After(startedAt) && gap > across {
			across, acrossAt = gap, seen[i].seq
		}
	}
	sort.Slice(gaps, func(a, b int) bool { return gaps[a] < gaps[b] })
	median := gaps[len(gaps)/2]
	worst := gaps[len(gaps)-1]

	t.Logf("switch lag: %v across the migration (frame %d), median gap %v, worst anywhere %v, %d frames at %v",
		across.Round(time.Millisecond), acrossAt, median.Round(time.Millisecond),
		worst.Round(time.Millisecond), frames, sendGap)

	if acrossAt < 0 {
		t.Fatal("no frame arrived across the migration window — the measurement proves nothing")
	}
	// Generous against a loaded CI box, and still a long way from the failure it guards: a migration
	// that ends up waiting on frameWait or exportWait shows up here as seconds, not milliseconds.
	if across > 500*time.Millisecond {
		t.Fatalf("the client waited %v across the switch (frame %d) — it felt the rollout", across, acrossAt)
	}
}

// echoBackend speaks the backend half of the protocol: it reads the PROXY header, echoes every frame
// after it, and closes when the proxy half-closes — which is what a node in handover mode does once
// it has written the session down.
type echoBackend struct {
	ln net.Listener
}

func newEchoBackend(t *testing.T) *echoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &echoBackend{ln: ln}
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer c.Close()
				if err := discardProxyHeader(c); err != nil {
					return
				}
				// io.Copy ends on the proxy's half-close, which is the export signal; closing then
				// is what tells the proxy the session is safe to move.
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *echoBackend) addr() string { return b.ln.Addr().String() }

// discardProxyHeader reads the v2 header, whose length is declared inside it.
func discardProxyHeader(c net.Conn) error {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(c, fixed); err != nil {
		return err
	}
	if !bytes.Equal(fixed[:12], []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")) {
		return io.ErrUnexpectedEOF
	}
	block := make([]byte, binary.BigEndian.Uint16(fixed[14:16]))
	_, err := io.ReadFull(c, block)
	return err
}
