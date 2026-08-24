package metrics

import (
	"strings"
	"testing"
	"time"
)

func render() string {
	var b strings.Builder
	WriteTo(&b)
	return b.String()
}

func valueOf(t *testing.T, out, line string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, line+" ") {
			return strings.TrimPrefix(l, line+" ")
		}
	}
	t.Fatalf("no sample named %q in:\n%s", line, out)
	return ""
}

// The counters have to move, not merely render. A metrics endpoint that always reports zero is worse
// than none: it answers the question wrongly and confidently.
func TestCountersMove(t *testing.T) {
	Routed("http")
	Routed("tcp")
	Routed("tcp")
	InspectFailed()
	DialFailed()
	ProxyHeaderSent()
	Upstream(1500)
	Downstream(9000)

	out := render()
	if got := valueOf(t, out, `watershed_connections_total{route="http"}`); got != "1" {
		t.Errorf("http route = %s, want 1", got)
	}
	if got := valueOf(t, out, `watershed_connections_total{route="tcp"}`); got != "2" {
		t.Errorf("tcp route = %s, want 2", got)
	}
	if got := valueOf(t, out, `watershed_connection_errors_total{stage="inspect"}`); got != "1" {
		t.Errorf("inspect errors = %s, want 1", got)
	}
	if got := valueOf(t, out, `watershed_connection_errors_total{stage="dial"}`); got != "1" {
		t.Errorf("dial errors = %s, want 1", got)
	}
	if got := valueOf(t, out, `watershed_bytes_total{direction="upstream"}`); got != "1500" {
		t.Errorf("upstream bytes = %s, want 1500", got)
	}
	if got := valueOf(t, out, `watershed_bytes_total{direction="downstream"}`); got != "9000" {
		t.Errorf("downstream bytes = %s, want 9000", got)
	}
	if got := valueOf(t, out, "watershed_proxy_headers_total"); got != "1" {
		t.Errorf("proxy headers = %s, want 1", got)
	}
}

// The gauge has to come back down, or a proxy that has served traffic looks permanently busy.
func TestActiveGaugeGoesBothWays(t *testing.T) {
	before := valueOf(t, render(), "watershed_active_connections")

	ConnectionOpened()
	ConnectionOpened()
	if got := valueOf(t, render(), "watershed_active_connections"); got == before {
		t.Fatalf("gauge did not rise, still %s", got)
	}

	ConnectionClosed()
	ConnectionClosed()
	if got := valueOf(t, render(), "watershed_active_connections"); got != before {
		t.Fatalf("gauge = %s after closing both, want %s", got, before)
	}
}

// This is the pair that would have shown, in one glance, that classification was waiting out its
// deadline instead of deciding on the first bytes.
func TestInspectWaitIsRecordedInSeconds(t *testing.T) {
	Inspected(1500 * time.Millisecond)
	out := render()

	sum := valueOf(t, out, "watershed_inspect_wait_seconds_total")
	if !strings.HasPrefix(sum, "1.5") {
		t.Errorf("wait sum = %s, want it to start at 1.5 seconds", sum)
	}
	if got := valueOf(t, out, "watershed_inspect_total"); got != "1" {
		t.Errorf("inspect count = %s, want 1", got)
	}
}

// Prometheus rejects a scrape whose types are not declared, and a HELP line is what makes a
// dashboard legible to whoever did not write it.
func TestEveryMetricDeclaresHelpAndType(t *testing.T) {
	out := render()
	for _, name := range []string{
		"watershed_connections_total",
		"watershed_connection_errors_total",
		"watershed_active_connections",
		"watershed_bytes_total",
		"watershed_proxy_headers_total",
		"watershed_inspect_wait_seconds_total",
		"watershed_inspect_total",
	} {
		if !strings.Contains(out, "# HELP "+name+" ") {
			t.Errorf("%s has no HELP line", name)
		}
		if !strings.Contains(out, "# TYPE "+name+" ") {
			t.Errorf("%s has no TYPE line", name)
		}
	}
}
