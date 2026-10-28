package gsconnect

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

func get(t *testing.T, h http.Handler, target string) (int, string, http.Header) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	res, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func TestGameIDs(t *testing.T) {
	h := &Handler{Log: logx.Discard()}
	// Heroes V 1.60, Hammers of Fate 2.1, Tribes of the East 3.1
	for _, dp := range []string{"HEROES_657d2c2ebadc6a1d", "HEROES_f4609f85d388479e", "HEROES_29988429c481f219"} {
		code, body, hdr := get(t, h, "/gsinit.php?dp="+dp)
		if code != 200 || !strings.Contains(body, "RouterPort0=7777") || !strings.Contains(body, "NATServerPort0=7781") {
			t.Fatalf("%s: %d %q", dp, code, body)
		}
		if hdr.Get("Content-Disposition") != "attachment; filename=servers.ini" {
			t.Fatalf("headers %v", hdr)
		}
		// the address the request arrived on
		if !strings.Contains(body, "RouterIP0=127.0.0.1") || !strings.Contains(body, "CDKeyServerIP0=127.0.0.1") {
			t.Fatalf("addresses: %q", body)
		}
	}
	if code, body, _ := get(t, h, "/gsinit.php?dp=SPLINTERCELL3PC&user=noname"); code != 200 || !strings.Contains(body, "ProxyPort0=7780") {
		t.Fatalf("Splinter Cell: %d %q", code, body)
	}
	for target, want := range map[string]int{"/gsinit.php": 400, "/gsinit.php?dp=NOPE": 400, "/other.php?dp=HEROES_657d2c2ebadc6a1d": 400,
		"/console": 400, "/": 404, "/a/b?dp=x": 404} {
		if code, _, _ := get(t, h, target); code != want {
			t.Errorf("%s: %d, want %d", target, code, want)
		}
	}
}

func TestHostAndOffsetAndServerID(t *testing.T) {
	h := &Handler{Log: logx.Discard(), Host: "203.0.113.5", PortOffset: 100, ServerID: "00112233445566778899aabbccddeeff"}
	_, body, _ := get(t, h, "/gsinit.php?dp=HEROES_657d2c2ebadc6a1d")
	for _, want := range []string{"NATServerIP0=203.0.113.5", "RouterPort0=7877", "RouterLauncherPort0=7878", "[Servers]",
		"\nServerID=00112233445566778899aabbccddeeff\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q in %q", want, body)
		}
	}
	if strings.Contains(body, "127.0.0.1") {
		t.Errorf("file address left: %q", body)
	}
}

// The game uses its libcurl through http_proxy: the request line holds the whole URL.
func TestProxyStyleRequest(t *testing.T) {
	srv := httptest.NewServer(&Handler{Log: logx.Discard()})
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET http://gsconnect.ubisoft.com/gsinit.php?dp=HEROES_657d2c2ebadc6a1d HTTP/1.1\r\nHost: gsconnect.ubisoft.com\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "200 OK") || !strings.Contains(string(b), "IRCPort0=7779") {
		t.Fatalf("%q", b)
	}
}
