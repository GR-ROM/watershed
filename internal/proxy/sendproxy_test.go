package proxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"watershed/internal/config"
)

// startHeaderReader accepts one connection, reads a PROXY v2 header off it, and reports the source
// address it declared. Deliberately a hand-written reader rather than a call into the writer's own
// package: the point is that the bytes on the wire are what a foreign implementation would expect,
// not that they round-trip through their author.
func startHeaderReader(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fixed := make([]byte, 16)
		if _, err := readFull(conn, fixed); err != nil {
			got <- "read error: " + err.Error()
			return
		}
		if string(fixed[:12]) != "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" {
			got <- "bad signature"
			return
		}
		block := make([]byte, binary.BigEndian.Uint16(fixed[14:16]))
		if _, err := readFull(conn, block); err != nil {
			got <- "read error: " + err.Error()
			return
		}
		if fixed[13] != 0x11 || len(block) != 12 {
			got <- "unexpected family/length"
			return
		}
		got <- net.IP(block[:4]).String()
		conn.Write([]byte("TCP:"))
	}()
	return ln.Addr().String(), got
}

func readFull(c net.Conn, b []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// The whole point of the feature: a backend behind this proxy is told which client it is serving,
// instead of seeing the proxy for every connection.
func TestSendProxyAnnouncesTheClientToTheBackend(t *testing.T) {
	backendAddr, got := startHeaderReader(t)

	cfg := baseConfig(t, backendAddr, backendAddr)
	cfg.TCPBackend = config.Backend{
		Transport: config.TransportPlain,
		Addr:      backendAddr,
		SendProxy: true,
	}
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	defer conn.Close()
	// Not HTTP, so it takes the TCP route -- a VPN frame header, which is the traffic this exists for.
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x10, 'h', 'i'}); err != nil {
		t.Fatal(err)
	}

	select {
	case declared := <-got:
		local := conn.LocalAddr().(*net.TCPAddr)
		if declared != local.IP.String() {
			t.Fatalf("backend was told %q, client actually came from %q", declared, local.IP)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend never received a PROXY header")
	}
}

// Off by default, and the default has to stay silent: a backend that does not expect a header would
// read those 28 bytes as protocol and drop the connection.
func TestWithoutSendProxyNothingIsPrepended(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	first := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 6)
		if _, err := readFull(c, buf); err != nil {
			return
		}
		first <- buf
	}()

	cfg := baseConfig(t, ln.Addr().String(), ln.Addr().String())
	proxyAddr := startProxy(t, cfg)

	conn := dialProxy(t, proxyAddr, cfg.TLSCertFile)
	defer conn.Close()
	sent := []byte{0x00, 0x00, 0x00, 0x10, 'h', 'i'}
	if _, err := conn.Write(sent); err != nil {
		t.Fatal(err)
	}

	select {
	case b := <-first:
		if string(b) != string(sent) {
			t.Fatalf("backend saw % X first, want the client's own bytes % X", b, sent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend received nothing")
	}
}
