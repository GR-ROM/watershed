package backend

import (
	"testing"

	"watershed/internal/config"
)

func TestHolderStartsAtTheConfiguredBackend(t *testing.T) {
	be := config.Backend{Transport: config.TransportPlain, Addr: "10.0.0.1:1488", SendProxy: true}

	h := NewHolder(be, "inst-1")
	cur := h.Current()

	if cur.Backend.Addr != be.Addr || cur.InstanceID != "inst-1" {
		t.Fatalf("current = %+v, want the configured backend", cur)
	}
	if cur.Generation != 0 {
		t.Fatalf("generation = %d, want 0 before any switch", cur.Generation)
	}
}

func TestSwitchReplacesOnlyTheAddress(t *testing.T) {
	be := config.Backend{Transport: config.TransportTLS, Addr: "10.0.0.1:1488", SendProxy: true, CACertFile: "/ca.pem"}
	h := NewHolder(be, "inst-1")

	next := h.Switch("10.0.0.2:1488", "inst-2")

	if next.Backend.Addr != "10.0.0.2:1488" {
		t.Fatalf("addr = %s, want the new one", next.Backend.Addr)
	}
	// A rolling update replaces the process, not the way it is spoken to.
	if next.Backend.Transport != be.Transport || !next.Backend.SendProxy || next.Backend.CACertFile != be.CACertFile {
		t.Fatalf("switch changed how the backend is dialled: %+v", next.Backend)
	}
	if next.Generation != 1 || h.Current().Generation != 1 {
		t.Fatalf("generation = %d, want 1 after one switch", next.Generation)
	}
}

func TestSwitchingToTheSameAddressStillBumpsTheGeneration(t *testing.T) {
	h := NewHolder(config.Backend{Addr: "10.0.0.1:1488"}, "inst-1")

	first := h.Switch("10.0.0.1:1488", "inst-2")
	second := h.Switch("", "inst-3")

	if first.Generation != 1 || second.Generation != 2 {
		t.Fatalf("generations = %d, %d; want 1, 2 — asking twice is not an error", first.Generation, second.Generation)
	}
	if second.Backend.Addr != "10.0.0.1:1488" {
		t.Fatalf("an empty address must keep the current one, got %s", second.Backend.Addr)
	}
	if second.InstanceID != "inst-3" {
		t.Fatalf("instance = %s, want the one just switched to", second.InstanceID)
	}
}
