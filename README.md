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
never stalled. For HTTP the peek continues to the end of the header block — no
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
