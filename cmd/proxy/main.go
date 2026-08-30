// Command proxy runs watershed: a TLS-terminating TCP proxy that routes each
// connection to an HTTP or a generic backend based on the first decrypted bytes.
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"

	"watershed/internal/admin"
	"watershed/internal/config"
	"watershed/internal/metrics"
	"watershed/internal/proxy"
)

const shutdownGrace = 15 * time.Second

func main() {
	out, closeOut, err := logDestination()
	if err != nil {
		log.Fatalf("watershed fatal: %v", err)
	}
	defer closeOut()

	logger := log.New(out, "watershed ", log.LstdFlags|log.Lmsgprefix)

	if err := run(logger); err != nil {
		logger.Fatalf("fatal: %v", err)
	}
}

// startMetrics serves the Prometheus endpoint on its own listener, in the background.
//
// A separate address on purpose, and one that should not be public: the proxy's whole job is to look
// like an ordinary web server from outside, and an endpoint announcing "watershed_connections_total"
// undoes that in one request. Bind it to loopback or a private network and let the scraper reach it
// there.
//
// A failure to bind is logged and not fatal. Losing metrics is worth a line in the log; taking the
// proxy down over them is not, and this process is in the path of every client.
func startMetrics(addr string, srv *proxy.Server, logger *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		metrics.WriteTo(w)
	})

	// The rolling-update surface lives here rather than on its own port: it belongs to the same
	// private network as the metrics, and one listener is one thing to keep off the internet.
	// ADMIN_TOKEN empty leaves every state-changing endpoint refusing, which is the safe default
	// for a process in the path of every client.
	admin.New(srv, os.Getenv("ADMIN_TOKEN"), logger).Register(mux)
	if os.Getenv("ADMIN_TOKEN") == "" {
		logger.Printf("admin API is read-only: ADMIN_TOKEN is not set")
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Printf("metrics on %s/metrics, admin on %s/admin/*", addr, addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("metrics listener stopped: %v", err)
		}
	}()
}

// logDestination returns where the log goes: stderr, and additionally a file when LOG_FILE is set.
//
// The file exists for log readers that are not a person -- fail2ban tails one to ban an address that
// floods the listener, and it needs a path that survives a redeploy. A container's json log does not:
// it lives under the container id, so recreating the container moves it and the jail silently stops
// watching anything. Rotation is logrotate's job and must use copytruncate: the file is held open for
// the life of the process, so a rename would leave this writing to an unlinked inode.
func logDestination() (io.Writer, func(), error) {
	path := os.Getenv("LOG_FILE")
	if path == "" {
		return os.Stderr, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("LOG_FILE %s: %w", path, err)
	}
	return io.MultiWriter(os.Stderr, f), func() { f.Close() }, nil
}

func run(logger *log.Logger) error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return err
	}

	srv, err := proxy.New(cfg, logger)
	if err != nil {
		return err
	}

	// The instance behind the TCP backend, as the control plane knows it. It travels in the resume
	// key of a handover, so the new instance can tell "a connection the previous one exported" from
	// "someone else's". Empty until the first switch names one.
	srv.Backends().Switch(cfg.TCPBackend.Addr, os.Getenv("BACKEND_TCP_INSTANCE"))

	if addr := os.Getenv("METRICS_LISTEN_ADDR"); addr != "" {
		startMetrics(addr, srv, logger)
	}

	logger.Printf("listening on %s", ln.Addr())
	logger.Printf("http  backend: %s (%s)", cfg.HTTPBackend.Addr, cfg.HTTPBackend.Transport)
	logger.Printf("tcp   backend: %s (%s)", cfg.TCPBackend.Addr, cfg.TCPBackend.Transport)
	if len(cfg.Rules) > 0 {
		logger.Printf("routes: %d rule(s) from %s", len(cfg.Rules), cfg.RoutesFile)
		for i, r := range cfg.Rules {
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			logger.Printf("  rule %s -> %s", name, r.Backend)
		}
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case s := <-sig:
		logger.Printf("received %s, shutting down", s)
		_ = ln.Close()
		srv.Shutdown(shutdownGrace)
		return nil
	}
}
