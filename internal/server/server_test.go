package server_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ports"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/server"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
)

func ini(t *testing.T, s *testserver.Server) string {
	res, err := http.Get("http://" + s.GSConnect() + "/gsinit.php?dp=HEROES_657d2c2ebadc6a1d")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestServerID(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ubigs.db")
	s := testserver.Start(t, func(c *server.Config) { c.DB = db })
	id := s.ServerID()
	if len(id) != 32 || !strings.Contains(ini(t, s), "ServerID="+id) {
		t.Fatalf("id %q in %q", id, ini(t, s))
	}
	s.Stop()
	// kept in the database
	s = testserver.Start(t, func(c *server.Config) { c.DB = db })
	if s.ServerID() != id {
		t.Fatalf("id changed across a restart: %s, %s", id, s.ServerID())
	}
	s.Stop()
	// the override wins
	s = testserver.Start(t, func(c *server.Config) { c.DB = db; c.ServerID = "FFEEDDCCBBAA99887766554433221100" })
	if s.ServerID() != "ffeeddccbbaa99887766554433221100" || !strings.Contains(ini(t, s), "ServerID=ffeeddccbbaa99887766554433221100") {
		t.Fatalf("override: %s", s.ServerID())
	}
	// memory: one per run
	m1 := testserver.Start(t, nil)
	m2 := testserver.Start(t, nil)
	if m1.ServerID() == m2.ServerID() {
		t.Fatal("two memory servers share an id")
	}
}

func TestEveryServiceAnswers(t *testing.T) {
	s := testserver.Start(t, nil)
	for _, port := range []int{env.PortRouter, env.PortRouterWM, env.PortProxy, env.PortProxyWM, env.PortLobby} {
		// two clients at once, the first one silent
		first, err := gsclient.New("", s.Addr(port), gsm.PartyRouter)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := gsclient.New("", s.Addr(port), gsm.PartyRouter)
		for _, c := range []*gsclient.Client{second, first} {
			res, err := c.Request(gsm.STILLALIVE)
			if err != nil || res.Header.Type != gsm.STILLALIVE || res.Header.Size != 6 {
				t.Fatalf("port %d: %v %v", port, res, err)
			}
		}
		first.Close()
		second.Close()
	}
}

func TestLimits(t *testing.T) {
	s := testserver.Start(t, func(c *server.Config) { c.MaxPerIP = 2; c.SocketTimeout = time.Second })
	a, _ := gsclient.New("", s.Addr(env.PortRouter), gsm.PartyRouter)
	b, _ := gsclient.New("", s.Addr(env.PortRouter), gsm.PartyRouter)
	c, _ := gsclient.New("", s.Addr(env.PortRouter), gsm.PartyRouter)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	if _, err := c.Request(gsm.STILLALIVE); err == nil {
		t.Fatal("third connection from one address served")
	}
	if _, err := a.Request(gsm.STILLALIVE); err != nil {
		t.Fatal(err)
	}
	// silent connections are closed after the timeout, freeing their slot
	time.Sleep(2500 * time.Millisecond)
	d, _ := gsclient.New("", s.Addr(env.PortRouter), gsm.PartyRouter)
	defer d.Close()
	if _, err := d.Request(gsm.STILLALIVE); err != nil {
		t.Fatalf("after the timeout: %v", err)
	}
	// a bad message closes only its own connection
	e, _ := gsclient.New("", s.Addr(env.PortRouter), gsm.PartyRouter)
	defer e.Close()
	e.SendRaw([]byte{0, 0, 6, 1, 0xFE, 0x42})
	if _, err := e.Recv(time.Second); err == nil {
		t.Fatal("bad message answered")
	}
	if _, err := d.Request(gsm.STILLALIVE); err != nil {
		t.Fatal(err)
	}
}

func TestBindError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	taken := ln.Addr().(*net.TCPAddr).Port
	cfg := testserver.Config()
	cfg.PortOffset = taken - env.PortLobby
	cfg.GSConnectPort = taken + 1000
	if cfg.PortOffset < -7000 {
		t.Skip("port too low")
	}
	_, err = server.Start(context.Background(), cfg, logx.Discard())
	var be *server.BindError
	if !errors.As(err, &be) {
		t.Fatalf("Start: %v", err)
	}
	if want := "lobby can't listen on TCP port " + strconv.Itoa(taken) + ": another program is already using it"; !strings.Contains(be.Message, want) {
		t.Fatalf("message %q", be.Message)
	}
	if ports.Classify(be.Err) != ports.InUse {
		t.Fatal("not classified as in use")
	}
	// nothing stays open: the other ports are free again
	l2, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(env.PortRouter+cfg.PortOffset))
	if err != nil {
		t.Fatalf("router port left open: %v", err)
	}
	l2.Close()
}
