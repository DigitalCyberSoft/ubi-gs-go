// Package gsconnect serves gsconnect.ubisoft.com: gsinit.php returns the game's servers.ini with the
// services' address filled in for each request.
package gsconnect

import (
	_ "embed"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

//go:embed static/servers.ini
var serversINI string

//go:embed static/GS.ini
var splinterCellINI string

var (
	heroesID = regexp.MustCompile(`^HEROES_[a-f0-9]{16}$`)
	ipLine   = regexp.MustCompile(`(?m)^(\w+IP\d+)=.*$`)
	portLine = regexp.MustCompile(`(?m)^\w+Port\d+=\d+$`)
)

// Splinter Cell: Chaos Theory ids, served their own file as the reference does.
var splinterCell = map[string]bool{
	"SPLINTERCELL3PS2US": true, "SPLINTERCELL3PC": true, "SPLINTERCELL3PCCOOP": true, "SPLINTERCELL3PCADVERS": true,
}

// Handler serves gsinit.php.
type Handler struct {
	Log *logx.Logger
	// Host is the services' address (UBIGS_HOST); empty means the local address the request arrived on.
	Host string
	// PortOffset moves the services' ports.
	PortOffset int
	// ServerID is added to servers.ini as ServerID=<hex>: HommaRe derives its login token from it.
	ServerID string
}

// ServersINI returns servers.ini with every *IP<n> line set to host (unless empty) and every
// *Port<n> line moved by offset.
func ServersINI(host string, offset int, serverID string) string {
	ini := serversINI
	if serverID != "" {
		// the file has the [Servers] section only, so the key goes at its end
		ini = strings.TrimRight(ini, "\r\n") + "\nServerID=" + serverID + "\n"
	}
	if host != "" {
		ini = ipLine.ReplaceAllString(ini, "${1}="+host)
	}
	if offset != 0 {
		ini = portLine.ReplaceAllStringFunc(ini, func(line string) string {
			key, value, _ := strings.Cut(line, "=")
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return line
			}
			return key + "=" + strconv.Itoa(n+offset)
		})
	}
	return ini
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Log.Infof("%s %s %s", netsrv.HostIP(remoteAddr(r)), r.Method, r.URL.RequestURI())
	// one path segment, as the reference's /<php_filename> route
	name := strings.TrimPrefix(r.URL.Path, "/")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if name == "" || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	dp, ok := r.URL.Query()["dp"]
	if !ok || len(dp) == 0 {
		http.Error(w, "Missing game id", http.StatusBadRequest)
		return
	}
	if name != "gsinit.php" {
		h.Log.Infof("unknown request for %s", name)
		http.Error(w, "Unknown request", http.StatusBadRequest)
		return
	}
	var file, body string
	switch {
	case heroesID.MatchString(dp[0]):
		// Heroes V and its expansions; the services' address is where this request arrived
		file, body = "servers.ini", ServersINI(h.host(r), h.PortOffset, h.ServerID)
	case splinterCell[dp[0]]:
		file, body = "GS.ini", splinterCellINI
	default:
		h.Log.Infof("unknown game id %q", dp[0])
		http.Error(w, "Unknown game id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+file)
	w.Write([]byte(body))
}

func (h *Handler) host(r *http.Request) string {
	if h.Host != "" {
		return h.Host
	}
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return netsrv.HostIP(a)
	}
	return ""
}

type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

func remoteAddr(r *http.Request) net.Addr { return addr(r.RemoteAddr) }
