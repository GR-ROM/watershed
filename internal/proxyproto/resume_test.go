package proxyproto

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func tcpAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolve %s: %v", s, err)
	}
	return a
}

// header layout: 12-byte signature, version/command, family, 2-byte length, then that many bytes.
func declaredLength(t *testing.T, header []byte) int {
	t.Helper()
	if len(header) < 16 {
		t.Fatalf("header is %d bytes, too short to have a length", len(header))
	}
	return int(binary.BigEndian.Uint16(header[14:16]))
}

func TestResumeTLVRidesInsideTheDeclaredLength(t *testing.T) {
	var buf bytes.Buffer
	src, dst := tcpAddr(t, "203.0.113.7:5555"), tcpAddr(t, "198.51.100.1:443")

	if err := WriteV2WithTLV(&buf, src, dst, ResumeTLV("inst-blue", 42)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := buf.Bytes()
	length := declaredLength(t, got)
	if want := len(got) - 16; length != want {
		t.Fatalf("declared length %d, want %d — a receiver would stop in the wrong place", length, want)
	}
	// The address block is still first, so a reader that skips the TLVs finds the addresses where
	// it always did.
	if length <= inetBlock {
		t.Fatalf("length %d leaves no room for a TLV after the 12-byte address block", length)
	}
	if !bytes.Contains(got, []byte("inst-blue:42")) {
		t.Fatal("the resume key is not in the header")
	}
}

func TestHeaderWithoutTLVsIsUnchanged(t *testing.T) {
	src, dst := tcpAddr(t, "203.0.113.7:5555"), tcpAddr(t, "198.51.100.1:443")

	var plain, viaTLV bytes.Buffer
	if err := WriteV2(&plain, src, dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteV2WithTLV(&viaTLV, src, dst); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !bytes.Equal(plain.Bytes(), viaTLV.Bytes()) {
		t.Fatal("adding no TLVs must produce exactly the header the backend already accepts")
	}
	if got := declaredLength(t, plain.Bytes()); got != inetBlock {
		t.Fatalf("length %d, want %d for a plain IPv4 header", got, inetBlock)
	}
}

func TestResumeTLVOnALocalHeader(t *testing.T) {
	var buf bytes.Buffer
	// Not TCP addresses: the header goes out as LOCAL, and the TLV still has to fit in its length.
	if err := WriteV2WithTLV(&buf, &net.UnixAddr{Name: "/x"}, &net.UnixAddr{Name: "/y"},
		ResumeTLV("inst-green", 7)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := buf.Bytes()
	if want := len(got) - 16; declaredLength(t, got) != want {
		t.Fatalf("declared length %d, want %d", declaredLength(t, got), want)
	}
	if !bytes.Contains(got, []byte("inst-green:7")) {
		t.Fatal("the resume key must survive a LOCAL header too")
	}
}

func TestAnOversizedTLVIsDroppedNotTruncated(t *testing.T) {
	var buf bytes.Buffer
	src, dst := tcpAddr(t, "203.0.113.7:5555"), tcpAddr(t, "198.51.100.1:443")
	huge := TLV{Type: TypeResume, Value: []byte(strings.Repeat("x", 0x10000))}

	if err := WriteV2WithTLV(&buf, src, dst, huge); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Half a resume key is worse than none: the backend would look up a record that does not exist
	// and quietly treat a handover as a new client.
	if got := declaredLength(t, buf.Bytes()); got != inetBlock {
		t.Fatalf("length %d, want %d — the oversized block must be dropped whole", got, inetBlock)
	}
}

// A write that fails must surface: the resume key is announced before the handshake, and a session
// whose header was half-written would be resumed by nobody and dropped by everybody.
func TestWriteV2WithTLVReportsAWriteFailure(t *testing.T) {
	err := WriteV2WithTLV(failingWriter{}, tcpAddr(t, "203.0.113.7:4242"), tcpAddr(t, "198.51.100.1:1488"),
		ResumeTLV("inst-blue", 7))
	if err == nil {
		t.Fatal("a failed write must be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), "write proxy header") {
		t.Fatalf("the error must say what could not be written, got %v", err)
	}
}
