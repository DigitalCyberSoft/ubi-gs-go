// Package ports explains a port that can't be opened in one line: which service, protocol and port,
// why, and what to do, for Linux, macOS and Windows.
package ports

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ExitBind is the exit code when a port can't be opened.
const ExitBind = 2

// Port is a service's port.
type Port struct {
	Service string // internal name, e.g. "router_wm"
	Proto   string // "tcp" or "udp"
	Port    int
}

// Names are the services' names in messages.
var Names = map[string]string{
	"gsconnect": "gsconnect", "router": "router", "irc": "IRC chat", "cdkey": "CD key", "nat": "NAT",
	"router_wm": "router wait module", "proxy": "proxy", "proxy_wm": "proxy wait module", "lobby": "lobby",
	"relay": "relay",
}

// Windows (Winsock) error codes.
const (
	wsaEACCES        = 10013
	wsaEADDRINUSE    = 10048
	wsaEADDRNOTAVAIL = 10049
)

// Readme points at the documentation for the fixes.
const Readme = `README.md, "Running it publicly" and "Troubleshooting ports"`

func errno(err error) (uintptr, string, bool) {
	var e syscall.Errno
	if errors.As(err, &e) {
		return uintptr(e), e.Error(), true
	}
	return 0, "", false
}

// Kind classifies a bind error.
type Kind int

// Bind error kinds.
const (
	Other Kind = iota
	InUse
	Access
	NotAvailable
)

// Classify returns the kind of a bind error, with Windows' Winsock codes.
func Classify(err error) Kind {
	code, _, ok := errno(err)
	if !ok {
		return Other
	}
	switch code {
	case uintptr(syscall.EADDRINUSE), wsaEADDRINUSE:
		return InUse
	case uintptr(syscall.EACCES), wsaEACCES:
		return Access
	case uintptr(syscall.EADDRNOTAVAIL), wsaEADDRNOTAVAIL:
		return NotAvailable
	}
	return Other
}

// FindCommand is the command that shows which program uses a port.
func FindCommand(proto string, port int, goos string) string {
	switch goos {
	case "windows":
		return fmt.Sprintf(`netstat -ano -p %s | findstr :%d  (then: tasklist /FI "PID eq <pid>")`, strings.ToUpper(proto), port)
	case "darwin":
		return fmt.Sprintf("sudo lsof -nP -i %s:%d", strings.ToUpper(proto), port)
	}
	flag := "t"
	if proto == "udp" {
		flag = "u"
	}
	return fmt.Sprintf("sudo ss -l%snp 'sport = :%d'", flag, port)
}

// Message is the one-line explanation of a bind error. owner describes the program holding the port,
// if known.
func Message(p Port, host string, err error, goos, owner string) string {
	name := Names[p.Service]
	if name == "" {
		name = p.Service
	}
	where := fmt.Sprintf("%s can't listen on %s port %d", name, strings.ToUpper(p.Proto), p.Port)
	windows := goos == "windows"
	switch Classify(err) {
	case InUse:
		holder := ""
		if owner != "" {
			holder = " (" + owner + ")"
		}
		return fmt.Sprintf("%s: another program is already using it%s. Stop that program (or the other copy of this server) and start again. Find it with: %s",
			where, holder, FindCommand(p.Proto, p.Port, goos))
	case Access:
		if windows {
			tables := "netsh int ipv4 show excludedportrange protocol=" + p.Proto
			if p.Port == 80 && p.Proto == "tcp" {
				return fmt.Sprintf(`%s: Windows refused access. Port 80 is usually held by HTTP.sys (the "System" process: IIS, the World Wide Web Publishing Service or another HTTP.sys user), or it is in a port range reserved by Hyper-V/WSL/Docker. Check with: netsh http show servicestate  and  %s`,
					where, tables)
			}
			return fmt.Sprintf("%s: Windows refused access. The port is in a range reserved by Hyper-V/WSL/Docker, or another program holds it exclusively. Check with: %s  and  %s",
				where, tables, FindCommand(p.Proto, p.Port, goos))
		}
		if p.Port < 1024 {
			return fmt.Sprintf("%s: ports below 1024 need root. Don't run the server as root; give the binary the capability (sudo setcap cap_net_bind_service=+ep ./ubi-gs), use systemd's AmbientCapabilities=CAP_NET_BIND_SERVICE, or run gsconnect on a high port (--gsconnect-port 8080) behind a reverse proxy on port 80. See %s",
				where, Readme)
		}
		_, text, _ := errno(err)
		return fmt.Sprintf("%s: permission denied (%s). A security policy (SELinux, AppArmor, a container) may forbid it.", where, text)
	case NotAvailable:
		return fmt.Sprintf("%s: the address %s is not on this machine. Listen on 0.0.0.0 (all interfaces) or on one of this machine's own addresses.",
			where, host)
	}
	if _, text, ok := errno(err); ok {
		return fmt.Sprintf("%s: %s.", where, text)
	}
	return fmt.Sprintf("%s: %v.", where, err)
}

// Explain is Message for this system, naming the program that holds a port in use when it can.
func Explain(p Port, host string, err error) string {
	owner := ""
	if Classify(err) == InUse {
		owner = Owner(p.Proto, p.Port)
	}
	return Message(p, host, err, runtime.GOOS, owner)
}

// Owner describes the program listening on a port, best effort.
func Owner(proto string, port int) string {
	switch runtime.GOOS {
	case "windows":
		ctx := exec.Command("netstat", "-ano", "-p", strings.ToUpper(proto))
		out, err := runTimeout(ctx, 5*time.Second)
		if err != nil {
			return ""
		}
		return NetstatOwner(proto, port, out)
	case "linux":
		return procOwner(proto, port)
	}
	return ""
}

func runTimeout(cmd *exec.Cmd, d time.Duration) (string, error) {
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
		return string(out), err
	case <-time.After(d):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", errors.New("timed out")
	}
}

// NetstatOwner finds the PID listening on a port in `netstat -ano` output.
func NetstatOwner(proto string, port int, output string) string {
	for _, line := range strings.Split(output, "\n") {
		cols := strings.Fields(line)
		if len(cols) < 4 || !strings.EqualFold(cols[0], proto) {
			continue
		}
		local := cols[1]
		if i := strings.LastIndex(local, ":"); i < 0 || local[i+1:] != strconv.Itoa(port) {
			continue
		}
		if proto == "tcp" && !strings.Contains(strings.ToUpper(line), "LISTEN") {
			continue
		}
		pid := cols[len(cols)-1]
		if pid == "4" {
			return `PID 4, "System", i.e. HTTP.sys`
		}
		return "PID " + pid
	}
	return ""
}

// procOwner finds the process listening on a port in /proc (only processes this user may inspect).
func procOwner(proto string, port int) string {
	inodes := map[string]bool{}
	for _, table := range []string{"/proc/net/" + proto, "/proc/net/" + proto + "6"} {
		f, err := os.Open(table)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan()
		for sc.Scan() {
			cols := strings.Fields(sc.Text())
			if len(cols) < 10 {
				continue
			}
			i := strings.LastIndex(cols[1], ":")
			p, err := strconv.ParseInt(cols[1][i+1:], 16, 32)
			// TCP listening (0A), UDP bound (07)
			if err == nil && int(p) == port && (cols[3] == "0A" || cols[3] == "07") {
				inodes["socket:["+cols[9]+"]"] = true
			}
		}
		f.Close()
	}
	if len(inodes) == 0 {
		return ""
	}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range pids {
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err == nil && inodes[link] {
				comm, _ := os.ReadFile(dir + "/comm")
				return fmt.Sprintf("PID %s, %s", filepath.Base(dir), strings.TrimSpace(string(comm)))
			}
		}
	}
	return "a process of another user"
}
