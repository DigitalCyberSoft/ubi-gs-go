package main

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseDefaultsAndEnv(t *testing.T) {
	for _, k := range []string{"UBIGS_BIND", "UBIGS_HOST", "UBIGS_DB", "UBIGS_RELAY", "UBIGS_MAX_PER_IP"} {
		t.Setenv(k, "")
	}
	o, err := parse(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	c := o.cfg
	if c.Bind != "0.0.0.0" || c.Host != "" || c.DB != "ubigs.db" || c.GSConnectPort != 80 || !c.Relay || c.MaxPerIP != 16 ||
		c.MaxConns != 512 || c.MaxNATClients != 4096 || c.MaxRooms != 512 || c.SocketTimeout != 180*time.Second || c.RelayMin != 9000 || c.RelayMax != 9999 {
		t.Fatalf("defaults %+v", c)
	}
	t.Setenv("UBIGS_BIND", "10.0.0.1")
	t.Setenv("UBIGS_HOST", "gs.example.org")
	t.Setenv("UBIGS_DB", ":memory:")
	t.Setenv("UBIGS_SOCKET_TIMEOUT", "60")
	t.Setenv("UBIGS_MAX_CONNECTIONS", "10")
	t.Setenv("UBIGS_MAX_PER_IP", "3")
	t.Setenv("UBIGS_MAX_NAT_CLIENTS", "20")
	t.Setenv("UBIGS_MAX_ROOMS", "3")
	t.Setenv("UBIGS_RELAY", "off")
	t.Setenv("UBIGS_RELAY_PORTS", "20000-20010")
	t.Setenv("UBIGS_SERVER_ID", "00112233445566778899aabbccddeeff")
	o, err = parse([]string{"--max-per-ip", "4"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	c = o.cfg
	if c.Bind != "10.0.0.1" || c.GSConnectBind != "10.0.0.1" || c.Host != "gs.example.org" || c.DB != ":memory:" || c.SocketTimeout != time.Minute ||
		c.MaxConns != 10 || c.MaxPerIP != 4 || c.MaxNATClients != 20 || c.MaxRooms != 3 || c.Relay || c.RelayMin != 20000 || c.ServerID == "" {
		t.Fatalf("from the environment %+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	for _, args := range [][]string{{"--relay-ports", "9-1"}, {"--server-id", "xyz"}, {"--quiet", "--verbose"}, {"extra"}, {"--socket-timeout", "0"}, {"--max-rooms", "0"}} {
		if _, err := parse(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	t.Setenv("UBIGS_MAX_PER_IP", "many")
	if _, err := parse(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "UBIGS_MAX_PER_IP") {
		t.Errorf("bad environment: %v", err)
	}
}

func TestHelp(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--help"}, &out, &out); code != 0 || !strings.Contains(out.String(), "UBIGS_RELAY_PORTS") || !strings.Contains(out.String(), "UBIGS_SOCKET_TIMEOUT") {
		t.Fatalf("help: %d %s", code, out.String())
	}
}

func TestPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var stdout, stderr bytes.Buffer
	code := run([]string{"--bind", "127.0.0.1", "--db", ":memory:", "--gsconnect-port", strconv.Itoa(port), "--port-offset", "21000", "--no-firewall-check"}, &stdout, &stderr)
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if code != 2 || len(lines) != 1 || !strings.HasPrefix(lines[0], "gsconnect can't listen on TCP port "+strconv.Itoa(port)+": another program is already using it") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}
