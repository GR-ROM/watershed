package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func tcp(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// The exact bytes the node's parser is written against. Kept as a literal rather than rebuilt from
// the same constants that produce it: a test that computes the answer the same way as the code
// agrees with the code by construction and proves nothing about the wire.
func TestWritesTheBytesTheSpecDescribes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteV2(&buf, tcp("92.46.76.70", 53653), tcp("87.106.204.29", 443)); err != nil {
		t.Fatal(err)
	}

	want := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,       // version 2, PROXY
		0x11,       // AF_INET, STREAM
		0x00, 0x0C, // 12 bytes follow
		0x5C, 0x2E, 0x4C, 0x46, // 92.46.76.70
		0x57, 0x6A, 0xCC, 0x1D, // 87.106.204.29
		0xD1, 0x95, // 53653
		0x01, 0xBB, // 443
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("header\n got % X\nwant % X", buf.Bytes(), want)
	}
	if buf.Len() != 28 {
		t.Fatalf("IPv4 header is %d bytes, want 28", buf.Len())
	}
}

// A receiver that does not expect a header must not mistake one for a frame: read as a big-endian
// length the signature is far past any sane packet ceiling, which is what makes a stray header fail
// loudly on the wrong port instead of being parsed as something.
func TestSignatureIsNotAPlausibleFrameLength(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteV2(&buf, tcp("1.2.3.4", 1), tcp("5.6.7.8", 2)); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(buf.Bytes()[:4]); got != 218762506 {
		t.Fatalf("signature as a length = %d, want 218762506", got)
	}
}

func TestIPv6(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteV2(&buf, tcp("2001:db8::1", 53653), tcp("2001:db8::2", 443)); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) != 52 {
		t.Fatalf("IPv6 header is %d bytes, want 52", len(b))
	}
	if b[13] != familyInet6Stream {
		t.Fatalf("family = %#x, want %#x", b[13], familyInet6Stream)
	}
	if got := binary.BigEndian.Uint16(b[14:16]); got != inet6Block {
		t.Fatalf("declared block = %d, want %d", got, inet6Block)
	}
	if !net.IP(b[16:32]).Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("source = %v", net.IP(b[16:32]))
	}
}

// A v4 client on a dual-stack listener arrives as ::ffff:a.b.c.d, so one end can be v4-mapped while
// the other is not. Both are widened: narrowing the destination would claim an address the client
// never connected to.
func TestMixedFamiliesAreWidenedNotNarrowed(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteV2(&buf, tcp("203.0.113.7", 1000), tcp("2001:db8::2", 443)); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) != 52 || b[13] != familyInet6Stream {
		t.Fatalf("want a 52-byte INET6 header, got %d bytes family %#x", len(b), b[13])
	}
	if !net.IP(b[16:32]).Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("source lost in translation: %v", net.IP(b[16:32]))
	}
}

// Anything that is not a TCP pair is announced as LOCAL: a well-formed header carrying no addresses,
// which the spec defines as "use the real ones". A receiver that requires a header still gets one.
func TestNonTCPBecomesLocal(t *testing.T) {
	cases := map[string][2]net.Addr{
		"unix":     {&net.UnixAddr{Name: "/tmp/s", Net: "unix"}, tcp("1.2.3.4", 1)},
		"udp":      {&net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}, tcp("1.2.3.4", 1)},
		"nil pair": {nil, nil},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteV2(&buf, pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
			b := buf.Bytes()
			if len(b) != 16 {
				t.Fatalf("LOCAL header is %d bytes, want 16", len(b))
			}
			if b[12] != versionCommandLocal {
				t.Fatalf("ver/cmd = %#x, want %#x", b[12], versionCommandLocal)
			}
			if got := binary.BigEndian.Uint16(b[14:16]); got != 0 {
				t.Fatalf("LOCAL declares %d bytes of addresses, want 0", got)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("socket gone") }

// The header is the first thing on the connection, so a failure here has to abort the connection
// rather than be swallowed: a backend that requires the header would otherwise be handed a stream
// that starts mid-protocol.
func TestWriteErrorIsReported(t *testing.T) {
	if err := WriteV2(failingWriter{}, tcp("1.2.3.4", 1), tcp("5.6.7.8", 2)); err == nil {
		t.Fatal("a failed write must be reported")
	}
}
