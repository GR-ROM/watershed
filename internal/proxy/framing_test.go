package proxy

import (
	"encoding/binary"
	"testing"
)

// frame builds one length-prefixed frame with a payload of n bytes.
func frame(n int) []byte {
	out := make([]byte, 4, 4+n)
	binary.BigEndian.PutUint32(out, uint32(n))
	for i := 0; i < n; i++ {
		out = append(out, byte('a'+i%26))
	}
	return out
}

func TestCursorStartsAndEndsAtBoundary(t *testing.T) {
	var c frameCursor
	if !c.atBoundary() {
		t.Fatal("a stream that has carried nothing is between frames")
	}

	buf := append(frame(3), frame(5)...)
	if got := c.advance(buf); got != len(buf) {
		t.Fatalf("last boundary = %d, want %d (both frames complete)", got, len(buf))
	}
	if !c.atBoundary() {
		t.Fatal("two whole frames leave the cursor between frames")
	}
}

func TestCursorReportsTheLastCompleteFrame(t *testing.T) {
	var c frameCursor
	whole := frame(4)
	buf := append(append([]byte{}, whole...), frame(100)[:10]...) // second frame cut short

	got := c.advance(buf)

	if got != len(whole) {
		t.Fatalf("last boundary = %d, want %d — only the first frame is complete", got, len(whole))
	}
	if c.atBoundary() {
		t.Fatal("a frame is still in flight, so the cursor is not at a boundary")
	}
}

func TestCursorHandlesALengthSplitAcrossReads(t *testing.T) {
	var c frameCursor
	f := frame(6)

	// The 4-byte length arrives one byte at a time, then the payload in two pieces.
	for i := 0; i < 4; i++ {
		if got := c.advance(f[i : i+1]); got != 0 {
			t.Fatalf("byte %d of the length must not report a boundary, got %d", i, got)
		}
		if c.atBoundary() {
			t.Fatalf("mid-length at byte %d is not a boundary", i)
		}
	}
	if got := c.advance(f[4:7]); got != 0 {
		t.Fatalf("half a payload is not a boundary, got %d", got)
	}
	if got := c.advance(f[7:]); got != 3 {
		t.Fatalf("boundary = %d, want 3 (the rest of the payload)", got)
	}
	if !c.atBoundary() {
		t.Fatal("the frame finished, so the cursor is between frames")
	}
}

func TestCursorFindsTheBoundaryInsideABulkRead(t *testing.T) {
	var c frameCursor
	first, second := frame(8), frame(1000)
	buf := append(append([]byte{}, first...), second[:20]...)

	got := c.advance(buf)

	if got != len(first) {
		t.Fatalf("boundary = %d, want %d", got, len(first))
	}
	// Everything after the boundary is what a migration would carry to the next backend.
	carried := len(buf) - got
	if carried != 20 {
		t.Fatalf("carried = %d, want 20", carried)
	}
}

func TestCursorTreatsAZeroLengthFrameAsABoundary(t *testing.T) {
	var c frameCursor
	buf := []byte{0, 0, 0, 0}

	if got := c.advance(buf); got != 4 {
		t.Fatalf("boundary = %d, want 4", got)
	}
	if !c.atBoundary() {
		t.Fatal("a zero-length frame must not stall the cursor")
	}
}
