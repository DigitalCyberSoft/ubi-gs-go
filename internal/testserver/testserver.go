// Package testserver starts a whole server on loopback for tests.
package testserver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/guard"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/server"
)

// Server is a running test server.
type Server struct {
	*server.Server
	Config server.Config
	cancel context.CancelFunc
}

// Config returns a loopback configuration: memory database, no relay, no limits on logins.
func Config() server.Config {
	g := guard.Defaults()
	g.LoginsPerIPMinute, g.NewAccountsPerIPHour = 0, 0
	return server.Config{
		Bind: "127.0.0.1", DB: ":memory:", SocketTimeout: 30 * time.Second, MaxConns: 512, MaxPerIP: 16,
		MaxNATClients: 4096, GSConnect: true, GSConnectBind: "127.0.0.1", RelayMin: 0, RelayMax: 0,
		Guard: g, FirewallCheck: false,
	}
}

// Start starts a server with the configuration on free ports; edit tweaks it first.
func Start(t testing.TB, edit func(*server.Config)) *Server {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		cfg := Config()
		cfg.PortOffset = 10000 + rand.IntN(40000)/10*10
		cfg.GSConnectPort = cfg.PortOffset + env.PortRouter + 9
		cfg.RelayMin = cfg.PortOffset + env.PortRouter + 100
		cfg.RelayMax = cfg.RelayMin + 50
		if edit != nil {
			edit(&cfg)
		}
		level := logx.Quiet
		if os.Getenv("UBIGS_TEST_LOG") != "" {
			level = logx.Verbose
		}
		ctx, cancel := context.WithCancel(context.Background())
		s, err := server.Start(ctx, cfg, logx.New(os.Stderr, level))
		if err != nil {
			cancel()
			var be *server.BindError
			if errors.As(err, &be) {
				lastErr = err
				continue
			}
			t.Fatal(err)
		}
		ts := &Server{Server: s, Config: cfg, cancel: cancel}
		t.Cleanup(ts.Stop)
		return ts
	}
	t.Fatalf("no free ports: %v", lastErr)
	return nil
}

// Stop stops the server.
func (s *Server) Stop() {
	s.cancel()
	s.Shutdown()
}

// Addr is a service's address.
func (s *Server) Addr(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port+s.Config.PortOffset))
}

// GSConnect is gsconnect's address.
func (s *Server) GSConnect() string { return fmt.Sprintf("127.0.0.1:%d", s.Config.GSConnectPort) }

// NeedLoopbackAliases skips a test on systems where 127.0.0.2 etc. can't be used as a source address.
func NeedLoopbackAliases(t testing.TB) {
	if runtime.GOOS != "linux" {
		t.Skip("needs 127.0.0.x source addresses (Linux)")
	}
}
