GO      ?= go
BIN     ?= build/proxy
CERTDIR ?= certs

.PHONY: all build test race cover certs clean fmt

all: build

build:
	$(GO) build -o $(BIN) ./cmd/proxy

test:
	$(GO) vet ./...
	$(GO) test ./... -count=1

# Requires cgo and a C toolchain, hence kept out of `test`.
# Repeats and varied GOMAXPROCS because a race only shows under the right schedule.
race:
	CGO_ENABLED=1 $(GO) test ./... -race -count=5 -cpu=1,2,4

cover:
	$(GO) test ./... -count=1 -cover

fmt:
	$(GO) fmt ./...

# Self-signed certificate for local development. Requires openssl.
certs:
	mkdir -p $(CERTDIR)
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout $(CERTDIR)/proxy-key.pem -out $(CERTDIR)/proxy.pem \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

clean:
	rm -rf build $(CERTDIR)
