# Static binary, then nothing else. The proxy opens listening sockets, reads two PEM files and dials
# backends; it has no use for a shell, a package manager or a libc, and every one of those is a thing
# an attacker who reaches this container would otherwise find waiting.
FROM golang:1.27-alpine AS build
WORKDIR /src

# Dependencies first so the module layer survives a source change. There is no go.sum in this module
# yet (no external dependencies), hence the wildcard.
COPY go.mod go.su[m] ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO off is what makes the binary runnable on scratch. Trimpath and the empty build id keep the
# image reproducible; -s -w drop the symbol table, which is 30% of a Go binary and of no use here.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid=" -o /proxy ./cmd/proxy

FROM scratch

# The proxy verifies backend certificates against the system pool when a backend is TLS and no
# BACKEND_*_CA_CERT_FILE is given. scratch has no pool, so bring one.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /proxy /proxy

# The default listener. Certificates and backends come from the environment; nothing is baked in,
# because the same image fronts different nodes.
EXPOSE 4430

ENTRYPOINT ["/proxy"]
