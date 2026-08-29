package proxy

import "encoding/binary"

// headerSize is the length prefix itself, which the declared length includes.
const headerSize = 4

// frameCursor tracks where the backend protocol's frame boundaries fall in the client→backend
// stream, without parsing anything inside a frame.
//
// It exists for one reason: a connection may only be moved to another backend instance between
// frames. Hand a backend half a frame and it reads the next four bytes as a length, gets nonsense,
// and closes — the client's tunnel dies, which is exactly what handover is meant to avoid.
//
// The framing is the node's: a 4-byte big-endian length, and that length COUNTS ITS OWN FOUR BYTES
// (protocol spec §3 — a 124-byte body goes on the wire as 0x00000080 = 128). Reading it as a body
// length overshoots by four bytes per frame, and the cursor then never sees a boundary again: every
// session reads as "mid-frame" and a rollout moves nobody. Measured on node-1, 2026-08-30.
//
// The cursor never buffers and never delays anything; it counts bytes as they go past, so the cost
// is a few integer operations per frame and the bulk copy keeps its 32 KiB reads.
type frameCursor struct {
	// remaining bytes of the frame currently in flight; 0 means the next byte starts a length.
	remaining uint32
	// header bytes of the next length seen so far (0..3), for a length split across two reads.
	header    [4]byte
	headerLen int
}

// atBoundary reports whether the stream is between frames right now.
func (c *frameCursor) atBoundary() bool {
	return c.remaining == 0 && c.headerLen == 0
}

// advance consumes n bytes of the stream and returns how far into buf the last frame boundary was —
// that is, the length of the prefix that can be forwarded while leaving the cursor at a boundary.
//
// The caller uses it two ways: normally it forwards everything and ignores the answer; when a
// migration is pending it forwards only up to the boundary and keeps the rest for the new backend.
func (c *frameCursor) advance(buf []byte) int {
	lastBoundary := 0
	i := 0
	for i < len(buf) {
		if c.remaining > 0 {
			n := len(buf) - i
			if uint32(n) > c.remaining {
				n = int(c.remaining)
			}
			c.remaining -= uint32(n)
			i += n
			if c.remaining == 0 {
				lastBoundary = i
			}
			continue
		}
		// Between frames: gather the 4-byte length, which may straddle two reads.
		c.header[c.headerLen] = buf[i]
		c.headerLen++
		i++
		if c.headerLen == 4 {
			declared := binary.BigEndian.Uint32(c.header[:])
			c.headerLen = 0
			if declared <= headerSize {
				// A frame that declares no body — not something this protocol sends, and a length
				// below the header is malformed. Either way the boundary is here: the node will
				// close on it if it disagrees, and stalling the cursor helps nobody.
				c.remaining = 0
				lastBoundary = i
			} else {
				c.remaining = declared - headerSize
			}
		}
	}
	return lastBoundary
}
