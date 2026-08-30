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

	// TypeResume is the TLV carrying a handover key: the connection being opened continues one that
	// another backend instance already knows, and the backend should restore that session instead of
	// treating the client as a stranger. It sits in the spec's PP2_TYPE_MIN_CUSTOM..MAX_CUSTOM range
	// (0xE0..0xEF), which exists for exactly this — a receiver that does not know the type skips it,
	// so a backend built before handover keeps working unchanged.
	TypeResume = 0xE0
)

// TLV is one type-length-value block, appended after the address block.
type TLV struct {
	Type  byte
	Value []byte
}

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
	return WriteV2WithTLV(w, src, dst)
}

// WriteV2WithTLV is WriteV2 plus trailing TLV blocks — used to carry a resume key on a connection
// that continues one from another backend instance (see TypeResume).
//
// The blocks go inside the length the header declares, which is what lets a receiver that does not
// know them skip the lot and still find the first payload byte.
func WriteV2WithTLV(w io.Writer, src, dst net.Addr, tlvs ...TLV) error {
	header, err := buildV2(src, dst, tlvs)
	if err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write proxy header: %w", err)
	}
	return nil
}

// ResumeTLV names a connection to the backend, as "instanceId:connId".
//
// The connection id is the PROXY's, not the node's, and that is the whole point: the proxy is the
// party that presents the key later, so it has to be the party that owns the name. The node learns
// its proxy-side id from this TLV at accept and files its exported session under it. Two counters,
// one on each side, was the first attempt — the node exported conn 166 while the proxy asked for
// conn 85, and nothing ever matched (node-1, 2026-08-30).
//
// instanceID is empty on a first dial: there is nothing to resume, and the TLV is there only to
// tell the node what this connection is called. On a re-dial it names the instance being left, and
// the node taking over looks that key up in the exported file.
func ResumeTLV(instanceID string, connID uint64) TLV {
	return TLV{Type: TypeResume, Value: []byte(fmt.Sprintf("%s:%d", instanceID, connID))}
}

func buildV2(src, dst net.Addr, tlvs []TLV) ([]byte, error) {
	extra := encodeTLVs(tlvs)

	srcTCP, srcOK := src.(*net.TCPAddr)
	dstTCP, dstOK := dst.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return localHeader(extra), nil
	}

	src4, dst4 := srcTCP.IP.To4(), dstTCP.IP.To4()
	if src4 != nil && dst4 != nil {
		return addressed(familyInetStream, inetBlock, src4, dst4, srcTCP.Port, dstTCP.Port, extra), nil
	}

	src16, dst16 := srcTCP.IP.To16(), dstTCP.IP.To16()
	if src16 == nil || dst16 == nil {
		// An address that is neither v4 nor v6 has nothing to describe.
		return localHeader(extra), nil
	}
	// One end v4 and the other v6 happens on a dual-stack listener, where a v4 client arrives as
	// ::ffff:a.b.c.d. Both are widened rather than one being narrowed: narrowing would claim a
	// destination the client never used.
	return addressed(familyInet6Stream, inet6Block, src16, dst16, srcTCP.Port, dstTCP.Port, extra), nil
}

// encodeTLVs lays each block out as type, 16-bit big-endian length, value. A value too long for that
// length is dropped rather than truncated: half a resume key is worse than none, because the
// receiver would look up a record that does not exist and silently treat a resumed client as new.
func encodeTLVs(tlvs []TLV) []byte {
	if len(tlvs) == 0 {
		return nil
	}
	var out []byte
	for _, t := range tlvs {
		if len(t.Value) > 0xFFFF {
			continue
		}
		out = append(out, t.Type)
		out = binary.BigEndian.AppendUint16(out, uint16(len(t.Value)))
		out = append(out, t.Value...)
	}
	return out
}

func addressed(family byte, block int, src, dst net.IP, srcPort, dstPort int, extra []byte) []byte {
	out := make([]byte, 0, 16+block+len(extra))
	out = append(out, signature...)
	out = append(out, versionCommandProxy, family)
	out = binary.BigEndian.AppendUint16(out, uint16(block+len(extra)))
	out = append(out, src...)
	out = append(out, dst...)
	out = binary.BigEndian.AppendUint16(out, uint16(srcPort))
	out = binary.BigEndian.AppendUint16(out, uint16(dstPort))
	return append(out, extra...)
}

func localHeader(extra []byte) []byte {
	out := make([]byte, 0, 16+len(extra))
	out = append(out, signature...)
	out = append(out, versionCommandLocal, 0x00)
	out = binary.BigEndian.AppendUint16(out, uint16(len(extra)))
	return append(out, extra...)
}
