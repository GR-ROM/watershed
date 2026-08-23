package router

import "testing"

func allBackends(string) bool { return true }

func mustRouter(t *testing.T, rules []Rule) *Router {
	t.Helper()
	rt, err := New(rules, allBackends)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rt
}

func req(method, path, host string, hdr map[string][]string) Request {
	if hdr == nil {
		hdr = map[string][]string{}
	}
	return Request{Method: method, Path: path, Host: host, Header: hdr}
}

func TestMatchByPath(t *testing.T) {
	rt := mustRouter(t, []Rule{
		{Name: "api", Backend: "api", Path: &StringMatch{Prefix: "/api/"}},
		{Name: "exact", Backend: "health", Path: &StringMatch{Equals: "/healthz"}},
		{Name: "assets", Backend: "cdn", Path: &StringMatch{Suffix: ".js"}},
		{Name: "versioned", Backend: "v2", Path: &StringMatch{Regex: `^/v[0-9]+/`}},
	})

	tests := []struct {
		path string
		want string
		ok   bool
	}{
		{"/api/users", "api", true},
		{"/api/", "api", true},
		{"/apix/users", "", false}, // prefix must not match a longer segment name
		{"/healthz", "health", true},
		{"/healthz/live", "", false}, // equals is exact
		{"/static/app.js", "cdn", true},
		{"/static/app.jsx", "", false},
		{"/v2/items", "v2", true},
		{"/v/items", "", false},
		{"/", "", false},
	}

	for _, tc := range tests {
		got, ok := rt.Match(req("GET", tc.path, "", nil))
		if ok != tc.ok || got != tc.want {
			t.Errorf("path %q: got (%q,%v), want (%q,%v)", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMatchByMethod(t *testing.T) {
	rt := mustRouter(t, []Rule{
		{Backend: "writes", Methods: []string{"POST", "PUT", "PATCH", "DELETE"}},
		{Backend: "reads", Methods: []string{"GET", "HEAD"}},
	})

	for _, tc := range []struct{ method, want string }{
		{"POST", "writes"},
		{"DELETE", "writes"},
		{"GET", "reads"},
		{"HEAD", "reads"},
	} {
		got, ok := rt.Match(req(tc.method, "/", "", nil))
		if !ok || got != tc.want {
			t.Errorf("method %s: got (%q,%v), want %q", tc.method, got, ok, tc.want)
		}
	}

	if _, ok := rt.Match(req("OPTIONS", "/", "", nil)); ok {
		t.Error("OPTIONS matched a rule it should not have")
	}
}

func TestMatchByHeader(t *testing.T) {
	rt := mustRouter(t, []Rule{
		{Name: "canary", Backend: "canary", Headers: []HeaderMatch{
			{Name: "X-Canary", StringMatch: StringMatch{Equals: "1"}},
		}},
		{Name: "any-auth", Backend: "private", Headers: []HeaderMatch{
			{Name: "Authorization", StringMatch: StringMatch{Exists: true}},
		}},
		{Name: "json", Backend: "api", Headers: []HeaderMatch{
			{Name: "Content-Type", StringMatch: StringMatch{Prefix: "application/json"}},
		}},
	})

	tests := []struct {
		name string
		hdr  map[string][]string
		want string
		ok   bool
	}{
		{"canary hit", map[string][]string{"X-Canary": {"1"}}, "canary", true},
		{"canary wrong value", map[string][]string{"X-Canary": {"0"}}, "", false},
		{"auth exists", map[string][]string{"Authorization": {"Bearer x"}}, "private", true},
		{"content type with charset", map[string][]string{
			"Content-Type": {"application/json; charset=utf-8"}}, "api", true},
		{"case-insensitive name", map[string][]string{"x-canary": {"1"}}, "canary", true},
		{"repeated header, one matches", map[string][]string{
			"X-Canary": {"0", "1"}}, "canary", true},
		{"nothing", map[string][]string{"User-Agent": {"curl"}}, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rt.Match(req("GET", "/", "", tc.hdr))
			if ok != tc.ok || got != tc.want {
				t.Fatalf("got (%q,%v), want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestMatchByHost(t *testing.T) {
	rt := mustRouter(t, []Rule{
		{Backend: "api", Host: &StringMatch{Equals: "api.example.com"}},
		{Backend: "wild", Host: &StringMatch{Regex: `\.internal$`}},
	})

	for _, tc := range []struct {
		host, want string
		ok         bool
	}{
		{"api.example.com", "api", true},
		{"svc.internal", "wild", true},
		{"example.com", "", false},
	} {
		got, ok := rt.Match(req("GET", "/", tc.host, nil))
		if ok != tc.ok || got != tc.want {
			t.Errorf("host %q: got (%q,%v), want (%q,%v)", tc.host, got, ok, tc.want, tc.ok)
		}
	}
}

// TestConditionsAreConjunctive pins the semantics: within one rule every stated
// condition must hold. Getting this wrong is the classic routing bug.
func TestConditionsAreConjunctive(t *testing.T) {
	rt := mustRouter(t, []Rule{{
		Name:    "post-to-api-with-token",
		Backend: "api",
		Methods: []string{"POST"},
		Path:    &StringMatch{Prefix: "/api/"},
		Headers: []HeaderMatch{{Name: "X-Token", StringMatch: StringMatch{Exists: true}}},
	}})

	full := req("POST", "/api/x", "", map[string][]string{"X-Token": {"t"}})
	if got, ok := rt.Match(full); !ok || got != "api" {
		t.Fatalf("all conditions met: got (%q,%v), want api", got, ok)
	}

	for _, miss := range []struct {
		name string
		r    Request
	}{
		{"wrong method", req("GET", "/api/x", "", map[string][]string{"X-Token": {"t"}})},
		{"wrong path", req("POST", "/other", "", map[string][]string{"X-Token": {"t"}})},
		{"missing header", req("POST", "/api/x", "", nil)},
	} {
		if _, ok := rt.Match(miss.r); ok {
			t.Errorf("%s: matched, but one condition was not satisfied", miss.name)
		}
	}
}

// TestFirstMatchWins pins the ordering contract.
func TestFirstMatchWins(t *testing.T) {
	rt := mustRouter(t, []Rule{
		{Name: "specific", Backend: "specific", Path: &StringMatch{Prefix: "/api/v2/"}},
		{Name: "general", Backend: "general", Path: &StringMatch{Prefix: "/api/"}},
	})

	if got, _ := rt.Match(req("GET", "/api/v2/x", "", nil)); got != "specific" {
		t.Fatalf("got %q, want specific: the earlier rule must win", got)
	}
	if got, _ := rt.Match(req("GET", "/api/v1/x", "", nil)); got != "general" {
		t.Fatalf("got %q, want general", got)
	}
}

func TestNoRulesMatchesNothing(t *testing.T) {
	rt := mustRouter(t, nil)
	if _, ok := rt.Match(req("GET", "/anything", "", nil)); ok {
		t.Fatal("an empty rule set matched a request")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
	}{
		{"no backend", []Rule{{Path: &StringMatch{Prefix: "/"}}}},
		{"no conditions", []Rule{{Backend: "api"}}},
		{"empty match", []Rule{{Backend: "api", Path: &StringMatch{}}}},
		{"two match kinds", []Rule{{Backend: "api",
			Path: &StringMatch{Equals: "/a", Prefix: "/b"}}}},
		{"bad regex", []Rule{{Backend: "api", Path: &StringMatch{Regex: "([a-z"}}}},
		{"exists on path", []Rule{{Backend: "api", Path: &StringMatch{Exists: true}}}},
		{"exists on host", []Rule{{Backend: "api", Host: &StringMatch{Exists: true}}}},
		{"header without name", []Rule{{Backend: "api",
			Headers: []HeaderMatch{{StringMatch: StringMatch{Equals: "x"}}}}}},
		{"lower-case method", []Rule{{Backend: "api", Methods: []string{"get"}}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.rules, allBackends); err == nil {
				t.Fatal("expected a validation error, got nil")
			}
		})
	}
}

// TestUnknownBackendRejectedAtStartup is what keeps a typo in the routes file
// from turning into a runtime surprise on one specific request.
func TestUnknownBackendRejectedAtStartup(t *testing.T) {
	known := func(n string) bool { return n == "api" }

	if _, err := New([]Rule{{Backend: "api", Path: &StringMatch{Prefix: "/"}}}, known); err != nil {
		t.Fatalf("known backend rejected: %v", err)
	}
	if _, err := New([]Rule{{Backend: "apy", Path: &StringMatch{Prefix: "/"}}}, known); err == nil {
		t.Fatal("a rule pointing at an unknown backend was accepted")
	}
}

func TestRulesAreCopied(t *testing.T) {
	rules := []Rule{{Backend: "api", Path: &StringMatch{Prefix: "/api/"}}}
	rt := mustRouter(t, rules)

	// Mutating the caller's slice must not change routing behaviour.
	rules[0].Backend = "hijacked"

	if got, _ := rt.Match(req("GET", "/api/x", "", nil)); got != "api" {
		t.Fatalf("got %q, want api: the router must not alias the caller's rules", got)
	}
}
