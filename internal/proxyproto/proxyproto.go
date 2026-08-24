// Package proxyproto writes the PROXY protocol v2 header that tells a backend which client a
// connection belongs to.
//
// A proxy that terminates TLS replaces the client's address with its own, and everything the backend
// does per address stops working: rate limits apply to the proxy, ban lists name the proxy, and an
// audit trail records the proxy. The header carries the address across that hop.
//
// v2 rather than v1: v1 is a text line terminated by a newline, so a reader has to scan for one, and
// a backend reading a binary protocol then needs a scanner it otherwise would not have. v2 is 16
// fixed bytes whose last two are the length of the rest, so a reader asks for exactly what it needs.
package proxyproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// signature opens every v2 header. Chosen by the spec so that a receiver which does not expect one
// cannot mistake it for anything else -- read as a 32-bit big-endian length it is 218 762 506.
var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	versionCommandProxy = 0x21 // version 2, command PROXY
	versionCommandLocal = 0x20 // version 2, command LOCAL: no addresses, use the real ones

	familyInetStream  = 0x11 // AF_INET  over SOCK_STREAM
	familyInet6Stream = 0x21 // AF_INET6 over SOCK_STREAM

	inetBlock  = 12 // 4 + 4 + 2 + 2
	inet6Block = 36 // 16 + 16 + 2 + 2
)

// WriteV2 writes a header describing a connection from src to dst.
//
// Both addresses are the CLIENT's view of the connection, not this proxy's view of the backend one:
// src is who connected, dst is the address they connected to. A backend reading the header learns
// what the client saw, which is the only reason to send it.
//
// A pair that is not TCP, or mixes IPv4 with IPv6, is written as LOCAL -- a well-formed header
// carrying no addresses, which the spec defines as "use the real ones". That keeps a receiver which
// requires a header from having to decide what a nonsensical one means.
func WriteV2(w io.Writer, src, dst net.Addr) error {
	header, err := buildV2(src, dst)
	if err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write proxy header: %w", err)
	}
	return nil
}

func buildV2(src, dst net.Addr) ([]byte, error) {
	srcTCP, srcOK := src.(*net.TCPAddr)
	dstTCP, dstOK := dst.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return localHeader(), nil
	}

	src4, dst4 := srcTCP.IP.To4(), dstTCP.IP.To4()
	if src4 != nil && dst4 != nil {
		return addressed(familyInetStream, inetBlock, src4, dst4, srcTCP.Port, dstTCP.Port), nil
	}

	src16, dst16 := srcTCP.IP.To16(), dstTCP.IP.To16()
	if src16 == nil || dst16 == nil {
		// An address that is neither v4 nor v6 has nothing to describe.
		return localHeader(), nil
	}
	// One end v4 and the other v6 happens on a dual-stack listener, where a v4 client arrives as
	// ::ffff:a.b.c.d. Both are widened rather than one being narrowed: narrowing would claim a
	// destination the client never used.
	return addressed(familyInet6Stream, inet6Block, src16, dst16, srcTCP.Port, dstTCP.Port), nil
}

func addressed(family byte, block int, src, dst net.IP, srcPort, dstPort int) []byte {
	out := make([]byte, 0, 16+block)
	out = append(out, signature...)
	out = append(out, versionCommandProxy, family)
	out = binary.BigEndian.AppendUint16(out, uint16(block))
	out = append(out, src...)
	out = append(out, dst...)
	out = binary.BigEndian.AppendUint16(out, uint16(srcPort))
	out = binary.BigEndian.AppendUint16(out, uint16(dstPort))
	return out
}

func localHeader() []byte {
	out := make([]byte, 0, 16)
	out = append(out, signature...)
	out = append(out, versionCommandLocal, 0x00)
	return binary.BigEndian.AppendUint16(out, 0)
}
