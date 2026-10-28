// Package server starts every Heroes V Game Service in one process: gsconnect (HTTP), the router and
// its wait module, the proxy and its wait module, the lobby, IRC chat, CD key (UDP), NAT (UDP) and the
// game traffic relay. They share accounts, lobby and NAT state in memory.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/cdkey"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/challenge"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/firewall"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsconnect"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/guard"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/irc"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/limits"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/lobby"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/nat"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ports"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/proxy"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ratings"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/relay"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/router"
)

// Config is the server's configuration.
type Config struct {
	Bind          string
	Host          string
	DB            string
	SocketTimeout time.Duration
	MaxConns      int
	MaxPerIP      int
	MaxNATClients int
	PortOffset    int

	GSConnect     bool
	GSConnectBind string
	GSConnectPort int

	Relay            bool
	RelayMin         int
	RelayMax         int
	RelayIdle        time.Duration
	RelayPacketsPerS float64
	RelayBytesPerS   float64

	// ServerID overrides the identity kept in the database (UBIGS_SERVER_ID).
	ServerID string

	Guard     guard.Config
	PruneDays int

	FirewallCheck bool
}

// BindError is a port that couldn't be opened, with its one-line explanation.
type BindError struct {
	Message string
	Err     error
}

func (e *BindError) Error() string { return e.Message }
func (e *BindError) Unwrap() error { return e.Err }

// Server is a running server.
type Server struct {
	cfg   Config
	log   *logx.Logger
	store *accounts.Store

	tcp    []*tcpService
	udp    []*net.UDPConn
	httpLn net.Listener
	http   *http.Server
	relay  *relay.Relay
	nat    *nat.Server
	lobby  *lobby.Lobby
	ports  []ports.Port
	// listeners are every TCP listener opened, closed together
	listeners []net.Listener
	// serverID is the identity in servers.ini
	serverID string
	wg       sync.WaitGroup
	started  chan struct{}
}

type tcpService struct {
	srv *netsrv.Server
	ln  net.Listener
}

// Ports lists every port the configuration listens on (the relay's range not included).
func (c Config) Ports() []ports.Port {
	p := env.DefaultPorts()
	o := c.PortOffset
	list := []ports.Port{}
	if c.GSConnect {
		list = append(list, ports.Port{Service: "gsconnect", Proto: "tcp", Port: c.GSConnectPort})
	}
	return append(list,
		ports.Port{Service: "router", Proto: "tcp", Port: p.Router + o},
		ports.Port{Service: "irc", Proto: "tcp", Port: p.IRC + o},
		ports.Port{Service: "cdkey", Proto: "udp", Port: p.CDKey + o},
		ports.Port{Service: "nat", Proto: "udp", Port: p.NAT + o},
		ports.Port{Service: "router_wm", Proto: "tcp", Port: p.RouterWM + o},
		ports.Port{Service: "proxy", Proto: "tcp", Port: p.Proxy + o},
		ports.Port{Service: "proxy_wm", Proto: "tcp", Port: p.ProxyWM + o},
		ports.Port{Service: "lobby", Proto: "tcp", Port: p.Lobby + o},
	)
}

// Start opens the database and every port, and starts the services. A port that can't be opened is a
// *BindError and nothing stays open.
func Start(ctx context.Context, cfg Config, log *logx.Logger) (_ *Server, err error) {
	s := &Server{cfg: cfg, log: log}
	defer func() {
		if err != nil {
			s.closeAll()
			if s.store != nil {
				s.store.Close()
			}
		}
	}()
	s.store, err = accounts.Open(cfg.DB, log.With("accounts").Warnf)
	if err != nil {
		return nil, fmt.Errorf("accounts database %s: %w", cfg.DB, err)
	}
	if cfg.DB == accounts.Memory {
		log.Infof("accounts are kept in memory only")
	} else {
		log.Infof("accounts database: %s", cfg.DB)
	}

	serverID := strings.ToLower(cfg.ServerID)
	if serverID == "" {
		if serverID, err = s.store.ServerID(); err != nil {
			return nil, fmt.Errorf("server id: %w", err)
		}
	}
	s.serverID = serverID
	log.Infof("server id: %s", serverID)

	off := cfg.PortOffset
	p := env.DefaultPorts()
	e := &env.Env{Accounts: s.store, Host: cfg.Host, Ports: env.Ports{
		Router: p.Router + off, IRC: p.IRC + off, CDKey: p.CDKey + off, NAT: p.NAT + off,
		RouterWM: p.RouterWM + off, Proxy: p.Proxy + off, ProxyWM: p.ProxyWM + off, Lobby: p.Lobby + off,
	}}
	s.ports = cfg.Ports()

	// every port first, so the server never runs with a service missing
	listeners := map[string]net.Listener{}
	for _, port := range s.ports {
		host := cfg.Bind
		if port.Service == "gsconnect" {
			host = cfg.GSConnectBind
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port.Port))
		if port.Proto == "udp" {
			ua, rerr := net.ResolveUDPAddr("udp4", addr)
			if rerr != nil {
				return nil, &BindError{ports.Explain(port, host, rerr), rerr}
			}
			c, lerr := net.ListenUDP("udp4", ua)
			if lerr != nil {
				return nil, &BindError{ports.Explain(port, host, lerr), lerr}
			}
			s.udp = append(s.udp, c)
			continue
		}
		ln, lerr := listenTCP(addr)
		if lerr != nil {
			return nil, &BindError{ports.Explain(port, host, lerr), lerr}
		}
		listeners[port.Service] = ln
		s.listeners = append(s.listeners, ln)
		if port.Service == "gsconnect" {
			s.httpLn = ln
		}
	}

	nonces := challenge.NewNonces()
	g := guard.New(s.store, cfg.Guard)
	g.Nonces = nonces
	rt := router.New(e, log.With("router"), log.With("router_wm"), g)
	px := &proxy.Proxy{Env: e, Log: log.With("proxy"), WMLog: log.With("proxy_wm")}
	s.lobby = lobby.New(e, log.With("lobby"))
	s.lobby.Results = &ratings.Ladder{Accounts: s.store, Log: log.With("ratings")}
	chat := irc.New(log.With("irc"), cfg.SocketTimeout)
	chat.Allowed = rt.LoggedIn
	s.nat = &nat.Server{Log: log.With("nat"), Port: e.Ports.NAT, MaxClients: cfg.MaxNATClients, MaxPerIP: cfg.MaxPerIP}

	if cfg.Relay {
		r, rerr := relay.New(relay.Config{Bind: cfg.Bind, Host: cfg.Host, PortMin: cfg.RelayMin, PortMax: cfg.RelayMax,
			MaxPerIP: cfg.MaxPerIP, Idle: cfg.RelayIdle, PacketsPerSecond: cfg.RelayPacketsPerS,
			BytesPerSecond: cfg.RelayBytesPerS}, log.With("relay"))
		if rerr != nil {
			return nil, rerr
		}
		r.Peers = s.lobby.Peers
		s.relay = r
		s.lobby.Relay = r
		s.lobby.Left = r.Forget
		s.nat.Relay = r
		log.Infof("relay on: game traffic goes through UDP ports %d-%d", cfg.RelayMin, cfg.RelayMax)
	}

	handlers := map[string]func(*netsrv.Conn){
		"router": rt.ServeRouter, "router_wm": rt.ServeWaitModule, "proxy": px.ServeProxy,
		"proxy_wm": px.ServeWaitModule, "lobby": s.lobby.Serve, "irc": chat.Serve,
	}
	for _, port := range s.ports {
		h, ok := handlers[port.Service]
		if !ok {
			continue
		}
		svc := &tcpService{ln: listeners[port.Service], srv: &netsrv.Server{
			Name: port.Service, Log: log.With(port.Service), Limits: limits.New(cfg.MaxConns, cfg.MaxPerIP),
			Timeout: cfg.SocketTimeout, Handle: h,
		}}
		s.tcp = append(s.tcp, svc)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			svc.srv.Serve(ctx, svc.ln)
		}()
		log.Infof("%s is listening on TCP port %d", ports.Names[port.Service], port.Port)
	}
	// UDP services, in port order: CD key, NAT
	cdkeyConn, natConn := s.udp[0], s.udp[1]
	s.wg.Add(2)
	go func() { defer s.wg.Done(); cdkey.Serve(cdkeyConn, log.With("cdkey")) }()
	go func() { defer s.wg.Done(); s.nat.Serve(natConn) }()
	log.Infof("CD key is listening on UDP port %d", e.Ports.CDKey)
	log.Infof("NAT is listening on UDP port %d", e.Ports.NAT)

	if s.httpLn != nil {
		s.http = &http.Server{
			Handler:           &gsconnect.Handler{Log: log.With("gsconnect"), Host: cfg.Host, PortOffset: off, ServerID: serverID, Nonces: nonces},
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.http.Serve(s.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Errorf("gsconnect: %v", err)
			}
		}()
		log.Infof("gsconnect is listening on TCP port %d", cfg.GSConnectPort)
	}
	if s.relay != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.relay.Run(ctx.Done()) }()
	}
	if cfg.PruneDays > 0 {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.prune(ctx) }()
	}
	return s, nil
}

func listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reuseAddr}
	return lc.Listen(context.Background(), "tcp4", addr)
}

// prune deletes accounts that never reached the lobby, at start and every hour.
func (s *Server) prune(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cutoff := time.Now().AddDate(0, 0, -s.cfg.PruneDays)
		if n, err := s.store.PruneUnused(cutoff); err != nil {
			s.log.Errorf("pruning accounts: %v", err)
		} else if n > 0 {
			s.log.Infof("pruned %d accounts that never reached the lobby in %d days", n, s.cfg.PruneDays)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// FirewallWarning returns the firewall check's warning, or "".
func (s *Server) FirewallWarning() string {
	var ranges []firewall.Range
	if s.cfg.Relay {
		ranges = append(ranges, firewall.Range{Proto: "udp", Min: s.cfg.RelayMin, Max: s.cfg.RelayMax})
	}
	return firewall.Check(s.ports, ranges)
}

// Accounts returns the accounts store.
func (s *Server) Accounts() *accounts.Store { return s.store }

// ServerID returns the server's identity.
func (s *Server) ServerID() string { return s.serverID }

// Relay returns the relay, or nil.
func (s *Server) Relay() *relay.Relay { return s.relay }

func (s *Server) closeAll() {
	for _, c := range s.udp {
		c.Close()
	}
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.http.Shutdown(ctx)
		cancel()
	} else if s.httpLn != nil {
		s.httpLn.Close()
	}
	for _, ln := range s.listeners {
		ln.Close()
	}
}

// Shutdown stops every service (the context given to Start must be done too) and closes the database.
func (s *Server) Shutdown() {
	s.closeAll()
	for _, t := range s.tcp {
		t.srv.Wait(3 * time.Second)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.log.Warnf("some services didn't stop in time")
	}
	if s.relay != nil {
		t := s.relay.Totals()
		s.log.Infof("relay: %d datagrams, %d bytes forwarded, %d dropped", t.Packets, t.Bytes, t.Dropped)
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			s.log.Errorf("closing the accounts database: %v", err)
		}
	}
}
