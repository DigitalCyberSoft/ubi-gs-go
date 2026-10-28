package ports

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func p(service, proto string, port int) Port { return Port{Service: service, Proto: proto, Port: port} }

func TestMessages(t *testing.T) {
	cases := []struct {
		port  Port
		err   error
		goos  string
		owner string
		want  []string
	}{
		{p("router", "tcp", 7777), syscall.EADDRINUSE, "linux", "PID 42, nginx",
			[]string{"router can't listen on TCP port 7777", "already using it (PID 42, nginx)", "ss -ltnp 'sport = :7777'"}},
		{p("cdkey", "udp", 7780), syscall.EADDRINUSE, "linux", "", []string{"CD key can't listen on UDP port 7780", "ss -lunp 'sport = :7780'"}},
		{p("gsconnect", "tcp", 80), syscall.EACCES, "linux", "",
			[]string{"TCP port 80", "need root", "setcap cap_net_bind_service", "reverse proxy", "AmbientCapabilities"}},
		{p("lobby", "tcp", 7785), syscall.Errno(10048), "windows", "", []string{"already using it", "netstat -ano -p TCP | findstr :7785", "tasklist"}},
		{p("gsconnect", "tcp", 80), syscall.Errno(10013), "windows", "",
			[]string{"HTTP.sys", "World Wide Web Publishing Service", "Hyper-V/WSL/Docker", "netsh http show servicestate", "excludedportrange protocol=tcp"}},
		{p("nat", "udp", 7781), syscall.Errno(10013), "windows", "", []string{"Hyper-V/WSL/Docker", "excludedportrange protocol=udp"}},
		{p("router", "tcp", 7777), syscall.EADDRNOTAVAIL, "linux", "", []string{"192.0.2.1 is not on this machine"}},
		{p("relay", "udp", 9000), syscall.EADDRINUSE, "darwin", "", []string{"relay can't listen on UDP port 9000", "lsof -nP -i UDP:9000"}},
	}
	for _, c := range cases {
		err := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", c.err)}
		msg := Message(c.port, "192.0.2.1", err, c.goos, c.owner)
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%v %s: no %q in %q", c.err, c.goos, w, msg)
			}
		}
		if strings.Contains(msg, "\n") {
			t.Errorf("more than one line: %q", msg)
		}
		if c.goos != "windows" && strings.Contains(msg, "HTTP.sys") {
			t.Errorf("Windows text on %s", c.goos)
		}
	}
	if msg := Message(p("nat", "udp", 7781), "", syscall.Errno(10013), "windows", ""); strings.Contains(msg, "HTTP.sys") {
		t.Errorf("UDP mentions HTTP.sys: %s", msg)
	}
	if msg := Message(p("router", "tcp", 7777), "", fmt.Errorf("odd"), "linux", ""); msg != "router can't listen on TCP port 7777: odd." {
		t.Errorf("other: %q", msg)
	}
}

func TestNetstatOwner(t *testing.T) {
	out := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:7777           0.0.0.0:0              LISTENING       5120
  TCP    127.0.0.1:7777         127.0.0.1:50000        ESTABLISHED     5120
`
	if got := NetstatOwner("tcp", 7777, out); got != "PID 5120" {
		t.Errorf("7777: %q", got)
	}
	if got := NetstatOwner("tcp", 80, out); !strings.Contains(got, "HTTP.sys") {
		t.Errorf("80: %q", got)
	}
	if got := NetstatOwner("tcp", 7785, out); got != "" {
		t.Errorf("7785: %q", got)
	}
	if got := NetstatOwner("udp", 7780, "  UDP    0.0.0.0:7780           *:*                                    888\n"); got != "PID 888" {
		t.Errorf("udp: %q", got)
	}
}

func TestRealBindError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	_, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if Classify(err) != InUse {
		t.Fatalf("%v not classified as in use", err)
	}
	msg := Explain(p("lobby", "tcp", port), "127.0.0.1", err)
	if !strings.Contains(msg, "another program is already using it") {
		t.Fatal(msg)
	}
	if runtime.GOOS == "linux" && !strings.Contains(msg, fmt.Sprintf("PID %d", os.Getpid())) {
		t.Errorf("owner not found: %s", msg)
	}
}
