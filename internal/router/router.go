// Package router decides which backend an HTTP request belongs to.
//
// Rules are evaluated in order and the first match wins. Within one rule every
// specified condition must hold, so a rule is a conjunction and the rule list
// is a disjunction. A request that matches nothing falls through to the default
// HTTP backend.
package router

import (
	"fmt"
	"regexp"
	"strings"
)

// StringMatch describes how one string is compared. Exactly one of the fields
// must be set, except Exists which stands alone and only applies to headers.
type StringMatch struct {
	Equals string `json:"equals,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
	Regex  string `json:"regex,omitempty"`
	Exists bool   `json:"exists,omitempty"`

	re *regexp.Regexp
}

// compile validates the match and prepares its regexp.
func (m *StringMatch) compile(where string) error {
	set := 0
	for _, s := range []string{m.Equals, m.Prefix, m.Suffix, m.Regex} {
		if s != "" {
			set++
		}
	}
	if m.Exists {
		set++
	}

	switch set {
	case 0:
		return fmt.Errorf("%s: empty match, set one of equals/prefix/suffix/regex/exists", where)
	case 1:
	default:
		return fmt.Errorf("%s: %d match kinds set, exactly one is allowed", where, set)
	}

	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		m.re = re
	}
	return nil
}

// matches reports whether v satisfies the comparison. present tells whether the
// value existed at all, which only differs from "" for headers.
func (m *StringMatch) matches(v string, present bool) bool {
	switch {
	case m.Exists:
		return present
	case !present:
		return false
	case m.Equals != "":
		return v == m.Equals
	case m.Prefix != "":
		return strings.HasPrefix(v, m.Prefix)
	case m.Suffix != "":
		return strings.HasSuffix(v, m.Suffix)
	case m.re != nil:
		return m.re.MatchString(v)
	}
	return false
}

// HeaderMatch selects a header by name and compares its value.
type HeaderMatch struct {
	Name string `json:"name"`
	// StringMatch is embedded so a header condition reads like any other match.
	StringMatch
}

// Rule routes a request to Backend when every stated condition holds.
type Rule struct {
	Name    string        `json:"name,omitempty"`
	Backend string        `json:"backend"`
	Methods []string      `json:"methods,omitempty"`
	Path    *StringMatch  `json:"path,omitempty"`
	Host    *StringMatch  `json:"host,omitempty"`
	Headers []HeaderMatch `json:"headers,omitempty"`
}

// Request is the subset of an HTTP request the router looks at.
type Request struct {
	Method string
	Path   string
	Host   string
	// Header keys are canonicalised, as produced by net/http.
	Header map[string][]string
}

// Router evaluates a compiled rule set.
type Router struct {
	rules []Rule
}

// New validates rules and returns a Router.
//
// backendExists lets the caller reject a rule pointing at an unknown backend at
// startup rather than at the first matching request.
func New(rules []Rule, backendExists func(string) bool) (*Router, error) {
	compiled := make([]Rule, len(rules))
	copy(compiled, rules)

	for i := range compiled {
		r := &compiled[i]
		where := ruleLabel(r, i)

		if r.Backend == "" {
			return nil, fmt.Errorf("%s: backend is required", where)
		}
		if backendExists != nil && !backendExists(r.Backend) {
			return nil, fmt.Errorf("%s: unknown backend %q", where, r.Backend)
		}
		if len(r.Methods) == 0 && r.Path == nil && r.Host == nil && len(r.Headers) == 0 {
			return nil, fmt.Errorf("%s: rule has no conditions and would match everything", where)
		}

		for j, m := range r.Methods {
			if m != strings.ToUpper(m) {
				return nil, fmt.Errorf("%s: method %q must be upper case", where, m)
			}
			r.Methods[j] = m
		}
		if r.Path != nil {
			if r.Path.Exists {
				return nil, fmt.Errorf("%s: path does not support \"exists\"", where)
			}
			if err := r.Path.compile(where + " path"); err != nil {
				return nil, err
			}
		}
		if r.Host != nil {
			if r.Host.Exists {
				return nil, fmt.Errorf("%s: host does not support \"exists\"", where)
			}
			if err := r.Host.compile(where + " host"); err != nil {
				return nil, err
			}
		}
		for j := range r.Headers {
			h := &r.Headers[j]
			if h.Name == "" {
				return nil, fmt.Errorf("%s: header %d has no name", where, j)
			}
			if err := h.compile(fmt.Sprintf("%s header %q", where, h.Name)); err != nil {
				return nil, err
			}
		}
	}

	return &Router{rules: compiled}, nil
}

func ruleLabel(r *Rule, i int) string {
	if r.Name != "" {
		return fmt.Sprintf("rule %q", r.Name)
	}
	return fmt.Sprintf("rule %d", i)
}

// Match returns the backend for req and true, or false when no rule applies.
func (rt *Router) Match(req Request) (string, bool) {
	for i := range rt.rules {
		if rt.rules[i].matches(req) {
			return rt.rules[i].Backend, true
		}
	}
	return "", false
}

// Rules exposes the compiled rules, mainly for logging and tests.
func (rt *Router) Rules() []Rule { return rt.rules }

func (r *Rule) matches(req Request) bool {
	if len(r.Methods) > 0 && !containsFold(r.Methods, req.Method) {
		return false
	}
	if r.Path != nil && !r.Path.matches(req.Path, true) {
		return false
	}
	if r.Host != nil && !r.Host.matches(req.Host, true) {
		return false
	}
	for i := range r.Headers {
		h := &r.Headers[i]
		values, ok := lookupHeader(req.Header, h.Name)
		if !ok {
			if !h.matches("", false) {
				return false
			}
			continue
		}
		// A header may repeat; any value satisfying the match is enough.
		hit := false
		for _, v := range values {
			if h.matches(v, true) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// containsFold compares methods case-sensitively, as RFC 9110 requires, but
// tolerates a lower-case list entry by comparing against its upper form.
func containsFold(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// lookupHeader is case-insensitive, matching HTTP semantics, without assuming
// the caller canonicalised the name.
func lookupHeader(h map[string][]string, name string) ([]string, bool) {
	if v, ok := h[name]; ok {
		return v, true
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}
