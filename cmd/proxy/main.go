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

	"watershed/internal/config"
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
