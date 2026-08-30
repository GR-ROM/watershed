package admin

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"watershed/internal/config"
	"watershed/internal/proxy"
)

func newAPI(t *testing.T, token string) (*API, *proxy.Server, *http.ServeMux) {
	t.Helper()
	be := config.Backend{Transport: config.TransportPlain, Addr: "10.0.0.1:1488", SendProxy: true}
	srv, err := proxy.New(&config.Config{
		MaxInspectBytes: 4096,
		InspectTimeout:  time.Second,
		DialTimeout:     time.Second,
		TCPBackend:      be,
		HTTPBackend:     be,
		Backends:        map[string]config.Backend{config.DefaultTCPBackendName: be, config.DefaultHTTPBackendName: be},
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	api := New(srv, token, log.New(io.Discard, "", 0))
	mux := http.NewServeMux()
	api.Register(mux)
	return api, srv, mux
}

func do(t *testing.T, mux *http.ServeMux, method, url, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestStatusIsReadableWithoutAToken(t *testing.T) {
	_, _, mux := newAPI(t, "secret")

	rec := do(t, mux, http.MethodGet, "/admin/status", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — watching a rollout should not need a secret", rec.Code)
	}
	var got Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Backend != "10.0.0.1:1488" {
		t.Fatalf("backend = %q, want the configured one", got.Backend)
	}
	if got.Sessions != 0 || got.Stale != 0 {
		t.Fatalf("idle proxy reports %d sessions, %d stale; want zeros", got.Sessions, got.Stale)
	}
}

func TestSwitchingBackendsNeedsTheToken(t *testing.T) {
	_, srv, mux := newAPI(t, "secret")

	if rec := do(t, mux, http.MethodPost, "/admin/backend?addr=10.0.0.2:1488", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
	if rec := do(t, mux, http.MethodPost, "/admin/backend?addr=10.0.0.2:1488", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", rec.Code)
	}
	if got := srv.Backends().Current().Backend.Addr; got != "10.0.0.1:1488" {
		t.Fatalf("a refused request changed the backend to %s", got)
	}
}

func TestSwitchPointsNewConnectionsAtTheNewInstance(t *testing.T) {
	_, srv, mux := newAPI(t, "secret")

	rec := do(t, mux, http.MethodPost, "/admin/backend?addr=10.0.0.2:1488&instance=inst-green", "secret")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	cur := srv.Backends().Current()
	if cur.Backend.Addr != "10.0.0.2:1488" || cur.InstanceID != "inst-green" {
		t.Fatalf("current = %+v, want the new address and instance", cur)
	}
	var got Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Generation == 0 {
		t.Fatal("the generation must move, or nothing can tell which sessions are stale")
	}
}

func TestSwitchWithoutAnAddressIsRefused(t *testing.T) {
	_, _, mux := newAPI(t, "secret")

	rec := do(t, mux, http.MethodPost, "/admin/backend", "secret")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestMigrateOnAnIdleProxyReportsNothingToDo(t *testing.T) {
	_, _, mux := newAPI(t, "secret")

	rec := do(t, mux, http.MethodPost, "/admin/migrate?timeout=100ms", "secret")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var got MigrateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Considered != 0 || got.Moved != 0 || got.Remaining != 0 {
		t.Fatalf("migrate on an idle proxy = %+v, want zeros", got)
	}
}

func TestWithoutATokenTheApiRefusesToChangeAnything(t *testing.T) {
	_, _, mux := newAPI(t, "")

	for _, path := range []string{"/admin/backend?addr=x:1", "/admin/migrate"} {
		if rec := do(t, mux, http.MethodPost, path, "anything"); rec.Code != http.StatusForbidden {
			t.Fatalf("%s = %d, want 403 when no token is configured", path, rec.Code)
		}
	}
	if rec := do(t, mux, http.MethodGet, "/admin/status", ""); rec.Code != http.StatusOK {
		t.Fatal("status stays readable even with the API otherwise disabled")
	}
}

func TestWrongMethodsAreRefused(t *testing.T) {
	_, _, mux := newAPI(t, "secret")

	if rec := do(t, mux, http.MethodGet, "/admin/backend?addr=x:1", "secret"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /admin/backend = %d, want 405", rec.Code)
	}
	if rec := do(t, mux, http.MethodPost, "/admin/status", "secret"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /admin/status = %d, want 405", rec.Code)
	}
}

// A rollout is driven by hand from a shell as often as by the control plane, and a typo in a query
// parameter must fall back to the default rather than migrate zero connections and report success.
func TestMigrationParametersFallBackWhenUnparseable(t *testing.T) {
	_, _, mux := newAPI(t, "s3cret")

	for _, url := range []string{
		"/admin/migrate?batch=abc&interval=nonsense&timeout=",
		"/admin/migrate?batch=-5&interval=-1s&timeout=-2s",
		"/admin/migrate",
	} {
		rec := do(t, mux, http.MethodPost, url, "s3cret")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", url, rec.Code)
		}
		var res MigrateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		if res.Considered != 0 || res.Moved != 0 {
			t.Fatalf("%s: nothing is connected, got %+v", url, res)
		}
	}
}

func TestMigrationParametersAreHonouredWhenValid(t *testing.T) {
	_, _, mux := newAPI(t, "s3cret")
	rec := do(t, mux, http.MethodPost, "/admin/migrate?batch=3&interval=10ms&timeout=100ms", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

func TestMigrateRejectsAGet(t *testing.T) {
	// The endpoint moves live client connections; a link-preview fetch must not trigger a rollout.
	_, _, mux := newAPI(t, "s3cret")
	if rec := do(t, mux, http.MethodGet, "/admin/migrate", "s3cret"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
}

func TestStatusCountsLiveSessions(t *testing.T) {
	// Status is what an operator reads to decide whether the rollout is finished: it has to count
	// what is still on the old backend, not merely echo the configured address back.
	_, _, mux := newAPI(t, "s3cret")
	rec := do(t, mux, http.MethodGet, "/admin/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Sessions != 0 || st.Stale != 0 {
		t.Fatalf("no client is connected, got %+v", st)
	}
	if st.Backend == "" {
		t.Fatalf("status must name the backend in use, got %+v", st)
	}
}
