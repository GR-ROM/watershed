// Package backend holds the TCP backend the proxy is currently sending connections to, and lets it
// be replaced at runtime.
//
// It exists for one operation: rolling a node without cutting anyone off. A new node instance comes
// up beside the old one, the proxy is told to point at it, and live connections are moved across one
// at a time (see proxy.Server.Migrate). Everything about that operation needs one place that answers
// "which backend is current", and it must answer without a lock on the accept path — hence an
// atomic pointer read per connection.
package backend

import (
	"sync"
	"sync/atomic"
	"time"

	"watershed/internal/config"
)

// Target is an immutable snapshot: a backend plus who it belongs to.
//
// InstanceID is the node instance behind this address. It travels in the resume key so the new
// instance can tell "a connection the previous instance exported" from "a connection some other
// instance exported", which is the difference between restoring a session and restoring someone
// else's session.
type Target struct {
	Backend    config.Backend
	InstanceID string
	// Generation increases with every switch; a connection remembers the generation it was dialled
	// on, so "are you on the current backend" is an integer comparison.
	Generation uint64
	SwitchedAt time.Time
}

// Holder is the current target, swappable at runtime and safe to read from any goroutine.
type Holder struct {
	current atomic.Pointer[Target]

	mu         sync.Mutex
	generation uint64
}

// NewHolder starts at the configured backend, generation 0.
func NewHolder(b config.Backend, instanceID string) *Holder {
	h := &Holder{}
	h.current.Store(&Target{Backend: b, InstanceID: instanceID, SwitchedAt: time.Now()})
	return h
}

// Current is the target new connections are dialled to. Never nil.
func (h *Holder) Current() *Target {
	return h.current.Load()
}

// Switch points new connections at addr and returns the new target.
//
// The address alone is replaced: transport, TLS material and the PROXY setting come from the
// configured backend, because a rolling update replaces the process, not the way it is spoken to.
// Switching to the address already in use is not an error and still bumps the generation — the
// operator asking twice should not have to care.
func (h *Holder) Switch(addr, instanceID string) *Target {
	h.mu.Lock()
	defer h.mu.Unlock()

	old := h.current.Load()
	next := &Target{
		Backend:    old.Backend,
		InstanceID: instanceID,
		Generation: h.generation + 1,
		SwitchedAt: time.Now(),
	}
	if addr != "" {
		next.Backend.Addr = addr
	}
	h.generation = next.Generation
	h.current.Store(next)
	return next
}
