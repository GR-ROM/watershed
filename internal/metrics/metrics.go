// Package metrics exposes what watershed is doing, in the Prometheus text format.
//
// Hand-written rather than pulled from a client library, because this module has no dependencies and
// the exposition format is a dozen lines of text. A proxy that fronts a VPN node is not the place to
// acquire a transitive tree.
//
// The counters were chosen by what went unanswered while this proxy was being brought up, not by
// what is easy to count. Two are worth naming. InspectWait is the time between a connection arriving
// and being classified: a bug once held every non-HTTP connection for the full inspect timeout, and
// the only symptom was that clients felt slow -- this metric would have said so in one glance.
// ConnectionErrors is split by stage, because "the proxy is failing" is not actionable and "it is
// failing to dial the backend" is.
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

var (
	routedHTTP atomic.Uint64
	routedTCP  atomic.Uint64

	errInspect atomic.Uint64
	errDial    atomic.Uint64

	active atomic.Int64

	bytesUpstream   atomic.Uint64
	bytesDownstream atomic.Uint64

	proxyHeaders atomic.Uint64

	inspectWaitNanos atomic.Uint64
	inspectCount     atomic.Uint64
)

// Routed records a connection that reached a backend, by which route it took.
func Routed(protocol string) {
	if protocol == "http" {
		routedHTTP.Add(1)
		return
	}
	routedTCP.Add(1)
}

// InspectFailed records a connection that never got far enough to be classified.
func InspectFailed() { errInspect.Add(1) }

// DialFailed records a connection classified but whose backend could not be reached.
func DialFailed() { errDial.Add(1) }

// ConnectionOpened and ConnectionClosed bracket a connection's life, for the active gauge.
func ConnectionOpened() { active.Add(1) }

// ConnectionClosed is the other half of ConnectionOpened.
func ConnectionClosed() { active.Add(-1) }

// Inspected records how long classification took, which is the number that says whether the
// classifier is deciding on the first bytes or waiting out its deadline.
func Inspected(d time.Duration) {
	if d > 0 {
		inspectWaitNanos.Add(uint64(d.Nanoseconds()))
	}
	inspectCount.Add(1)
}

// Upstream and Downstream count payload bytes in each direction, client to backend and back.
func Upstream(n int64) {
	if n > 0 {
		bytesUpstream.Add(uint64(n))
	}
}

// Downstream is the other direction.
func Downstream(n int64) {
	if n > 0 {
		bytesDownstream.Add(uint64(n))
	}
}

// ProxyHeaderSent records a PROXY v2 header written to a backend.
func ProxyHeaderSent() { proxyHeaders.Add(1) }

// WriteTo renders every counter in the Prometheus text exposition format.
func WriteTo(w io.Writer) {
	p := func(format string, args ...any) {
		fmt.Fprintf(w, format, args...)
	}

	p("# HELP watershed_connections_total Connections routed to a backend, by route.\n")
	p("# TYPE watershed_connections_total counter\n")
	p("watershed_connections_total{route=\"http\"} %d\n", routedHTTP.Load())
	p("watershed_connections_total{route=\"tcp\"} %d\n", routedTCP.Load())

	p("# HELP watershed_connection_errors_total Connections that never reached a backend, by stage.\n")
	p("# TYPE watershed_connection_errors_total counter\n")
	p("watershed_connection_errors_total{stage=\"inspect\"} %d\n", errInspect.Load())
	p("watershed_connection_errors_total{stage=\"dial\"} %d\n", errDial.Load())

	p("# HELP watershed_active_connections Connections currently being proxied.\n")
	p("# TYPE watershed_active_connections gauge\n")
	p("watershed_active_connections %d\n", active.Load())

	p("# HELP watershed_bytes_total Payload bytes spliced, by direction.\n")
	p("# TYPE watershed_bytes_total counter\n")
	p("watershed_bytes_total{direction=\"upstream\"} %d\n", bytesUpstream.Load())
	p("watershed_bytes_total{direction=\"downstream\"} %d\n", bytesDownstream.Load())

	p("# HELP watershed_proxy_headers_total PROXY v2 headers announced to a backend.\n")
	p("# TYPE watershed_proxy_headers_total counter\n")
	p("watershed_proxy_headers_total %d\n", proxyHeaders.Load())

	// A sum and a count rather than a histogram: the question is "is classification instant or is it
	// waiting for the deadline", and a mean answers it. Buckets can come the day it does not.
	p("# HELP watershed_inspect_wait_seconds_total Time spent classifying connections.\n")
	p("# TYPE watershed_inspect_wait_seconds_total counter\n")
	p("watershed_inspect_wait_seconds_total %f\n", float64(inspectWaitNanos.Load())/1e9)
	p("# HELP watershed_inspect_total Connections classified.\n")
	p("# TYPE watershed_inspect_total counter\n")
	p("watershed_inspect_total %d\n", inspectCount.Load())
}
