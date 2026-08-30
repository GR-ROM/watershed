# watershed

A TLS-terminating TCP proxy. It decrypts client traffic, looks at the first
bytes to decide where the stream belongs, and forwards the connection to a
backend — each backend independently reachable over plain TCP or TLS, optionally
with a client certificate.

Non-HTTP streams go to a single generic backend. HTTP streams can be routed by
**rules** on path, method, host and headers, so several services can sit behind
one TLS endpoint.

After the routing decision the proxy is a transparent byte pipe: it never
rewrites, buffers or interprets payload.

## How a connection flows

```
client --TLS--> [ watershed ] --plain or TLS--> backend
                    |
                    +-- 1. terminate client TLS
                    +-- 2. peek at the head of the stream (bounded by size and time)
                    +-- 3. not HTTP?  -> BACKEND_TCP_*
                    |      HTTP?      -> first matching rule, else BACKEND_HTTP_*
                    +-- 4. splice both directions until either side finishes
```

The peek is bounded two ways. `MAX_INSPECT_BYTES` caps how much is buffered, and
`INSPECT_TIMEOUT` caps how long watershed waits for it. Crucially the proxy does
**not** wait for the buffer to fill: a 40-byte request is classified as soon as
it arrives, so a client that sends a short request and waits for a reply is
never stalled.

That holds for binary protocols too, and used to not: until 2026-08-23 the
classifier only ran once a newline appeared in the buffer, so a stream that
never sends one was held until `INSPECT_TIMEOUT` fired. Every non-HTTP
connection paid it in full -- measured through a real proxy at 5266 ms to the
first protocol reply against 614 ms direct. A prefix that cannot still become an
HTTP request line is now decided on the spot, which for a binary protocol is
usually the first byte. For HTTP the peek continues to the end of the header block — no
further — so rules can match on headers while the body still streams straight
through. Every peeked byte is replayed to the backend verbatim.

### One decision per connection

Routing happens once, when the connection opens. After that watershed is a raw
tunnel and cannot re-read the stream, so with HTTP keep-alive a second request
on the same connection goes wherever the **first** one went.

This is inherent to proxying at the TCP layer. If you need per-request routing,
you need a full HTTP proxy that parses and re-emits every request — a different
program with different costs.

## Configuration

All settings come from the environment.

### Listener

| Variable | Default | Meaning |
| --- | --- | --- |
| `TLS_LISTEN_ADDR` | `:4430` | Address the proxy listens on |
| `TLS_CERT_FILE` | — | **Required.** Server certificate presented to clients |
| `TLS_KEY_FILE` | — | **Required.** Matching private key |

### Observability

| Variable | Default | Meaning |
| --- | --- | --- |
| `METRICS_LISTEN_ADDR` | — | Serves Prometheus metrics at `/metrics` **and the admin API at `/admin/*`** on this address; unset means neither |
| `ADMIN_TOKEN` | — | Secret for the state-changing admin endpoints (`X-Admin-Token`). Empty leaves them refusing with 403 — `/admin/status` stays readable |
| `BACKEND_TCP_INSTANCE` | — | Which node instance is behind `BACKEND_TCP_ADDR`, as the control plane names it. Travels in a handover's resume key |

**Do not make it public.** The proxy's job is to look like an ordinary web server from outside, and an
endpoint answering `watershed_connections_total` undoes that in one request. Bind it to loopback or a
private network and let the scraper reach it there. A failure to bind is logged and not fatal: losing
metrics is worth a line in the log, taking down a proxy that every client goes through is not.

Two of the series are worth knowing about. `watershed_inspect_wait_seconds_total` over
`watershed_inspect_total` is the mean time to classify a connection — a bug once held every non-HTTP
connection for the whole `INSPECT_TIMEOUT` and the only symptom was that clients felt slow; this ratio
says it in one glance. And `watershed_connection_errors_total` is split by stage, because "the proxy
is failing" is not actionable while "it cannot dial the backend" is.

## Rolling a backend without dropping anyone

The TCP backend can be replaced while the proxy runs, and live connections carried across to the new
instance. That is what makes a node update invisible: the client's TLS session is to this proxy, and
this proxy never lets go of it.

```bash
# 1. Point new connections at the new instance. Live ones stay where they are.
curl -XPOST -H "X-Admin-Token: $T" "$ADMIN/admin/backend?addr=172.30.0.11:1488&instance=inst-green"

# 2. Watch, then move the live ones across in batches.
curl -XPOST -H "X-Admin-Token: $T" "$ADMIN/admin/migrate?batch=10&interval=200ms&timeout=60s"
# {"considered":37,"moved":37,"remaining":0}

curl "$ADMIN/admin/status"
# {"backend":"172.30.0.11:1488","instanceId":"inst-green","generation":2,"sessions":37,"stale":0}
```

**How a connection moves.** Only the proxy can stop the client→backend direction somewhere safe, so
it does. It counts frames (the backend protocol is a 4-byte big-endian length, then that many
bytes), stops on a boundary, and half-closes the backend socket. The node reads that end-of-stream
as "no more client bytes are coming": it exports the session, flushes what it still owes the client,
and closes. Only then does the proxy dial the new instance, with the old instance's id and the
connection id in a PROXY v2 TLV (`0xE0`, `instanceId:connId`) so the new one restores that session
instead of seeing a stranger. Bytes that arrived after the boundary are carried across and written
there first, so a frame split by the move is reassembled whole.

Two things it will not do. A client that goes quiet **mid-frame** is left where it is — moving it
would hand one backend half a frame, and half a frame reads as a nonsense length and drops the
tunnel; `remaining` in the response counts those, and asking again usually moves them. And a backend
that never closes after the half-close is force-closed after ten seconds: losing one connection
beats hanging it forever.

HTTP connections (the decoy) are not tracked or migrated. They are short and stateless, and a
rollout has nothing to carry.

### Inspection and timeouts

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_INSPECT_BYTES` | `4096` | Upper bound on the peeked prefix |
| `INSPECT_TIMEOUT` | `5s` | How long to wait for the client's first bytes |
| `DIAL_TIMEOUT` | `10s` | Bound on establishing the backend connection |

### Backends

Two independent groups: `BACKEND_HTTP_*` for the HTTP route and `BACKEND_TCP_*`
for everything else. Both accept the same variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BACKEND_<X>_ADDR` | — | **Required.** `host:port` of the backend |
| `BACKEND_<X>_TYPE` | `plain` | `plain` or `tls` |
| `BACKEND_<X>_CA_CERT_FILE` | system pool | Trust anchor for verifying the backend |
| `BACKEND_<X>_CLIENT_CERT_FILE` | — | Client certificate for mTLS |
| `BACKEND_<X>_CLIENT_KEY_FILE` | — | Matching key; must be set together with the cert |
| `BACKEND_<X>_TLS_INSECURE_SKIP_VERIFY` | `false` | Skip verification — development only |
| `BACKEND_<X>_SEND_PROXY` | — | `v2` prepends a PROXY protocol v2 header so the backend learns the client's real address |

`SEND_PROXY` is written on the raw TCP connection **before** any TLS handshake, because that is where
a receiver has to read it: it decides whether to talk to this client at all before spending a
handshake on them. A backend that does not expect a header will refuse the connection — read as a
frame length the signature is 218 762 506 — so it is opt-in per backend and off by default.

TLS-only variables are ignored when `TYPE=plain`, so a half-edited environment
cannot silently change transports. Any invalid value is reported as a startup
error; the proxy never panics on configuration.

These two are also addressable by name from rules, as `http` and `tcp`.

## Rule-based HTTP routing

Set `ROUTES_FILE` to a JSON file to declare extra backends and the rules that
select them. Without it watershed behaves exactly as described above.

```json
{
  "backends": {
    "api":    { "addr": "127.0.0.1:9001" },
    "cdn":    { "addr": "cdn.internal:8443", "type": "tls", "caCertFile": "/etc/ssl/ca.pem" },
    "canary": { "addr": "127.0.0.1:9003" }
  },
  "rules": [
    { "name": "canary",  "backend": "canary", "headers": [{ "name": "X-Canary", "equals": "1" }] },
    { "name": "writes",  "backend": "api",    "methods": ["POST", "PUT", "PATCH", "DELETE"] },
    { "name": "api",     "backend": "api",    "path": { "prefix": "/api/" } },
    { "name": "assets",  "backend": "cdn",    "path": { "suffix": ".js" } },
    { "name": "by-host", "backend": "cdn",    "host": { "equals": "static.example.com" } }
  ]
}
```

**Evaluation.** Rules are tried in order and the first match wins, so put the
specific ones first. Within one rule every stated condition must hold — a rule
is an AND of its conditions. A request matching nothing falls through to
`BACKEND_HTTP_*`.

**Conditions.** A rule may combine any of:

| Field | Matches against |
| --- | --- |
| `methods` | the request method, upper case, any of the listed values |
| `path` | the request target with the query string stripped |
| `host` | the `Host` header with the port stripped |
| `headers` | a named header; repeated headers match if any value does |

`path`, `host` and each header take exactly one comparison: `equals`, `prefix`,
`suffix` or `regex` (RE2). A header may instead use `"exists": true` to match on
presence alone.

**Backends** declared in the file take `addr` (required), `type`, `caCertFile`,
`clientCertFile`, `clientKeyFile` and `insecureSkipVerify` — the same knobs the
environment offers. A name colliding with `http` or `tcp` is rejected.

**Everything is validated at startup**: an unknown backend, a bad regex, a rule
with no conditions, two comparisons in one match, or an unknown JSON field all
stop the proxy from starting. A typo must not become a routing surprise on one
unlucky request.

Two limits worth knowing. Header rules only see headers that arrived within
`MAX_INSPECT_BYTES`; a header block larger than that is matched on whatever was
read, which can turn into a false negative — raise the budget if you route on
headers that sit far down a large request. And routing is per connection, not
per request: see the note above about keep-alive.

## Running

Plain backends:

```sh
export TLS_CERT_FILE=./certs/proxy.pem
export TLS_KEY_FILE=./certs/proxy-key.pem
export BACKEND_HTTP_ADDR=127.0.0.1:8080
export BACKEND_TCP_ADDR=127.0.0.1:9090
go run ./cmd/proxy
```

Encrypted upstream with mutual TLS:

```sh
export TLS_CERT_FILE=./certs/proxy.pem
export TLS_KEY_FILE=./certs/proxy-key.pem
export BACKEND_HTTP_TYPE=tls
export BACKEND_HTTP_ADDR=backend.internal:8443
export BACKEND_HTTP_CA_CERT_FILE=./certs/ca.pem
export BACKEND_HTTP_CLIENT_CERT_FILE=./certs/client.pem
export BACKEND_HTTP_CLIENT_KEY_FILE=./certs/client-key.pem
export BACKEND_TCP_ADDR=127.0.0.1:9090
go run ./cmd/proxy
```

`SIGINT` or `SIGTERM` stops accepting, closes live connections and waits up to
15 seconds for handlers to drain.

## Development

```sh
make build   # binary into build/
make test    # go vet + full test suite
make cover   # per-package coverage
make certs   # self-signed development certificates into certs/
```

## Protocol detection

A stream is treated as HTTP when it starts with a known method token followed by
a space (`GET `, `POST `, `PUT `, `DELETE `, `HEAD `, `OPTIONS `, `PATCH `,
`CONNECT `, `TRACE `) and the first line carries an ` HTTP/` version token.

The version token is required because a raw TCP protocol may legitimately begin
with those same letters — `GETTING STARTED\r\n` routes to the TCP backend, not
the web one. When the request line has not fully arrived yet, a matching method
is accepted provisionally rather than stalling the connection.

Detection is case-sensitive, matching RFC 9110: `get / HTTP/1.1` is not a valid
request line and routes to the TCP backend.

## Tests

`make test` runs unit tests for configuration, detection and dialling, plus
end-to-end tests that stand up real TLS listeners with generated certificates
and assert that traffic reaches the correct backend byte-for-byte, including a
512 KiB payload that dwarfs the inspection buffer.

The suite is also clean under the race detector, which matters here because
every connection is handled by two concurrent copy goroutines over shared state:

```sh
make race    # CGO_ENABLED=1 go test ./... -race
```

`make race` needs cgo and a C toolchain, so it stays separate from `make test`.
It has been verified across 5 repetitions at `GOMAXPROCS` 1, 2 and 4 — a single
pass proves little, since a data race only surfaces under the right schedule.
