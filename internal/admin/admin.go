// Package admin exposes the few operations a control plane needs to roll a backend without
// dropping anyone: see where the proxy is pointing, point it somewhere else, and move the live
// connections across.
//
// HTTP rather than a socket the proxy opens outwards, and pull rather than push. The control plane
// already reaches this host over the service network — it scrapes the metrics endpoint next door —
// and a proxy that dials out would need a WebSocket client, a reconnect policy and a dependency, in
// a module that deliberately has none. What it costs is that the edge cannot announce itself; the
// control plane learns the same facts by asking.
//
// It shares the metrics listener, which must not be public: these endpoints change where every
// client's traffic goes. A token is required for anything that changes state.
package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"watershed/internal/metrics"
	"watershed/internal/proxy"
)

// Defaults for a migration when the caller does not say otherwise. Gentle on purpose: each move
// costs the node an export and the client a pause.
const (
	DefaultBatch    = 10
	DefaultInterval = 200 * time.Millisecond
	DefaultTimeout  = 60 * time.Second
)

// API serves the admin endpoints for one proxy.
type API struct {
	srv   *proxy.Server
	token string
	log   *log.Logger
}

// New returns an API. An empty token disables every state-changing endpoint — the same rule the
// node's own admin surface follows, so a host that forgot to configure one is inert rather than
// open.
func New(srv *proxy.Server, token string, logger *log.Logger) *API {
	return &API{srv: srv, token: token, log: logger}
}

// Register mounts the endpoints on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("/admin/status", a.status)
	mux.HandleFunc("/admin/backend", a.switchBackend)
	mux.HandleFunc("/admin/migrate", a.migrate)
}

// Status is what the control plane reads to follow a rollout.
type Status struct {
	Backend    string `json:"backend"`
	InstanceID string `json:"instanceId"`
	Generation uint64 `json:"generation"`
	// Sessions is every live connection on the TCP backend; Stale is how many of them are still on
	// an older instance and would move on the next migrate.
	Sessions int `json:"sessions"`
	Stale    int `json:"stale"`
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	// Status is readable without the token: it says how many connections there are, not who they
	// are, and a rollout is easier to watch when reading it needs no secret.
	cur := a.srv.Backends().Current()
	writeJSON(w, Status{
		Backend:    cur.Backend.Addr,
		InstanceID: cur.InstanceID,
		Generation: cur.Generation,
		Sessions:   a.srv.MigratableSessions(),
		Stale:      a.srv.StaleSessions(),
	})
}

// switchBackend points new connections at another address. Live ones stay where they are until
// /admin/migrate — two steps on purpose, so a rollout can put the new instance in the path and
// watch it before touching anyone who is already connected.
func (a *API) switchBackend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(w, r) {
		return
	}
	addr := r.URL.Query().Get("addr")
	instance := r.URL.Query().Get("instance")
	if addr == "" {
		http.Error(w, "addr is required", http.StatusBadRequest)
		return
	}

	next := a.srv.Backends().Switch(addr, instance)
	metrics.BackendSwitched()
	a.log.Printf("admin: new connections now go to %s (instance %s, generation %d)",
		next.Backend.Addr, next.InstanceID, next.Generation)

	if migrate, _ := strconv.ParseBool(r.URL.Query().Get("migrate")); migrate {
		a.runMigration(w, r)
		return
	}
	writeJSON(w, Status{
		Backend:    next.Backend.Addr,
		InstanceID: next.InstanceID,
		Generation: next.Generation,
		Sessions:   a.srv.MigratableSessions(),
		Stale:      a.srv.StaleSessions(),
	})
}

func (a *API) migrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(w, r) {
		return
	}
	a.runMigration(w, r)
}

// MigrateResponse reports one migration pass. Remaining above zero is not a failure: those clients
// were mid-frame and stayed where they are, and asking again usually moves them.
type MigrateResponse struct {
	Considered int `json:"considered"`
	Moved      int `json:"moved"`
	Remaining  int `json:"remaining"`
	// Failed counts clients dropped because the new backend could not be dialled — the one number
	// here that says a rollout hurt somebody, so it is reported rather than folded into Moved.
	Failed int `json:"failed"`
}

func (a *API) runMigration(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	batch := intParam(q.Get("batch"), DefaultBatch)
	interval := durationParam(q.Get("interval"), DefaultInterval)
	timeout := durationParam(q.Get("timeout"), DefaultTimeout)

	res := a.srv.Migrate(batch, interval, timeout)
	a.log.Printf("admin: migrated %d of %d live connection(s), %d left on the old backend, %d dropped",
		res.Moved, res.Considered, res.Remaining, res.Failed)
	writeJSON(w, MigrateResponse{Considered: res.Considered, Moved: res.Moved,
		Remaining: res.Remaining, Failed: res.Failed})
}

func (a *API) authorized(w http.ResponseWriter, r *http.Request) bool {
	if a.token == "" {
		http.Error(w, "admin API disabled: no token configured", http.StatusForbidden)
		return false
	}
	if r.Header.Get("X-Admin-Token") != a.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("encode: %v", err), http.StatusInternalServerError)
	}
}

func intParam(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func durationParam(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return def
	}
	return d
}
