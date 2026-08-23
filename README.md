# watershed

A TLS-terminating TCP proxy. It decrypts client traffic, looks at the first
bytes to decide whether the stream is HTTP or something else, and forwards the
connection to one of two configured backends — each independently reachable over
plain TCP or TLS (optionally with a client certificate).

After the routing decision the proxy is a transparent byte pipe: it never
rewrites, buffers or interprets payload.

## How a connection flows

```
client --TLS--> [ watershed ] --plain or TLS--> backend
                    |
                    +-- 1. terminate client TLS
                    +-- 2. peek at the first bytes (bounded by size and time)
                    +-- 3. HTTP request line?  -> BACKEND_HTTP_*
                    |      anything else       -> BACKEND_TCP_*
                    +-- 4. splice both directions until either side finishes
```

The peek is bounded two ways. `MAX_INSPECT_BYTES` caps how much is buffered, and
`INSPECT_TIMEOUT` caps how long watershed waits for it. Crucially the proxy does
**not** wait for the buffer to fill: a 40-byte request is classified as soon as
it arrives, so a client that sends a short request and waits for a reply is
never stalled. Every peeked byte is replayed to the backend verbatim.

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
