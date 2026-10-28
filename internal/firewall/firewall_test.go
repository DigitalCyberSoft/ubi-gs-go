package firewall

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ports"
)

func allPorts() []ports.Port {
	return []ports.Port{{Service: "gsconnect", Proto: "tcp", Port: 80}, {Service: "router", Proto: "tcp", Port: 7777}, {Service: "irc", Proto: "tcp", Port: 7779}, {Service: "cdkey", Proto: "udp", Port: 7780},
		{Service: "nat", Proto: "udp", Port: 7781}, {Service: "router_wm", Proto: "tcp", Port: 7782}, {Service: "proxy", Proto: "tcp", Port: 7783}, {Service: "proxy_wm", Proto: "tcp", Port: 7784}, {Service: "lobby", Proto: "tcp", Port: 7785}}
}

const netshAllow = `
Rule Name:                            ubi-gs
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Protocol:                             TCP
LocalPort:                            Any
Program:                              C:\Games\ubi-gs.exe
Action:                               Allow

Rule Name:                            ubi-gs
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Protocol:                             UDP
LocalPort:                            Any
Program:                              C:\Games\ubi-gs.exe
Action:                               Allow
Ok.
`

const netshTCP = `
Rule Name:                            ubi-gs TCP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Protocol:                             TCP
LocalPort:                            80,7777,7779,7782-7785
Program:                              Any
Action:                               Allow

Rule Name:                            Old rule
----------------------------------------------------------------------
Enabled:                              No
Direction:                            In
Protocol:                             UDP
LocalPort:                            7780-7781
Program:                              Any
Action:                               Allow
Ok.
`

const stateOn = "Domain Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\nOk.\n"

var programs = []string{`C:\Games\ubi-gs.exe`}

func TestWindows(t *testing.T) {
	if w := WindowsWarning(allPorts(), nil, netshAllow, stateOn, programs); w != "" {
		t.Errorf("allowed program warned: %s", w)
	}
	if w := WindowsWarning(allPorts(), nil, netshAllow, stateOn, []string{`C:\Other\ubi-gs.exe`}); !strings.Contains(w, "TCP 7777 (router): no rule allows it") {
		t.Errorf("other program: %s", w)
	}
	blocked := strings.Replace(netshAllow, "Action:                               Allow\n\nRule Name", "Action:                               Block\n\nRule Name", 1)
	w := WindowsWarning(allPorts(), nil, blocked, stateOn, programs)
	if !strings.Contains(w, `blocked by rule "ubi-gs"`) || !strings.Contains(w, "TCP 80 (gsconnect)") || strings.Contains(w, "UDP 7780") || !strings.Contains(w, "disable the blocking rules") {
		t.Errorf("blocked: %s", w)
	}
	w = WindowsWarning(allPorts(), []Range{{Proto: "udp", Min: 9000, Max: 9999}}, netshTCP, stateOn, programs)
	if !strings.Contains(w, "UDP 7780 (cdkey): no rule allows it") || strings.Contains(w, "TCP 7777") ||
		!strings.Contains(w, `netsh advfirewall firewall add rule name="ubi-gs UDP" dir=in action=allow protocol=UDP localport=7780,7781,9000-9999`) ||
		strings.Contains(w, "protocol=TCP") || !strings.Contains(w, "administrator") {
		t.Errorf("UDP missing: %s", w)
	}
	if w := WindowsWarning(allPorts(), nil, "", strings.Replace(stateOn, " ON", " OFF", 1), programs); w != "" {
		t.Errorf("firewall off: %s", w)
	}
	w = WindowsWarning(allPorts(), nil, "", "", programs)
	for _, want := range []string{"could not read", "TCP: 80,7777,7779,7782,7783,7784,7785", "UDP: 7780,7781",
		"protocol=TCP localport=80,7777,7779,7782,7783,7784,7785", "protocol=UDP localport=7780,7781"} {
		if !strings.Contains(w, want) {
			t.Errorf("unreadable rules: no %q in %s", want, w)
		}
	}
	rules := ParseNetshRules(netshTCP)
	if len(rules) != 2 || rules[0]["localport"] != "80,7777,7779,7782-7785" {
		t.Errorf("parse: %v", rules)
	}
}

func names(list []ports.Port) []string {
	var out []string
	for _, p := range list {
		out = append(out, p.Proto+"/"+itoa(p.Port))
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestFirewalldAndUfw(t *testing.T) {
	list := allPorts()[1:]
	missing := FirewalldMissing(list, "7777/tcp 7779-7785/tcp 7780/udp", "ssh http")
	if len(missing) != 1 || missing[0].Port != 7781 {
		t.Fatalf("firewalld %v", missing)
	}
	if h := LinuxHint(missing, "firewalld"); !strings.Contains(h, "--add-port=7781/udp") || strings.Contains(h, "\n") {
		t.Errorf("hint %s", h)
	}
	status := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n7777/tcp                   ALLOW       Anywhere\n7780                       ALLOW       Anywhere\n"
	missing = UfwMissing(list, status)
	got := strings.Join(names(missing), " ")
	if strings.Contains(got, "7777") || strings.Contains(got, "7780") || !strings.Contains(got, "tcp/7785") {
		t.Errorf("ufw %s", got)
	}
	if !strings.Contains(LinuxHint(missing, "ufw"), "sudo ufw allow 7785/tcp") {
		t.Error("ufw hint")
	}
}

const iptablesFedora = `-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,7777,7779 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
`

const iptablesDebian = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N game
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j game
-A game -p tcp -m tcp --dport 7777:7785 -j ACCEPT
-A game -p udp -m udp --dport 7780 -j ACCEPT
`

const iptablesSave = `# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
`

const nftRuleset = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		tcp dport 22 accept
		tcp dport { 80, 7777-7785 } accept
		jump game
	}
	chain game {
		udp dport 7780 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`

func TestRawLinux(t *testing.T) {
	if got := strings.Join(names(IptablesMissing(allPorts(), iptablesFedora)), " "); got != "tcp/7782 tcp/7783 tcp/7784 tcp/7785 udp/7780 udp/7781" {
		t.Errorf("fedora: %s", got)
	}
	if got := strings.Join(names(IptablesMissing(allPorts(), iptablesDebian)), " "); got != "tcp/80 udp/7781" {
		t.Errorf("debian: %s", got)
	}
	got := strings.Join(names(IptablesMissing(allPorts(), iptablesSave)), " ")
	if strings.Contains(got, "tcp/80 ") || !strings.Contains(got, "tcp/7777") || !strings.Contains(got, "udp/7780") {
		t.Errorf("save format: %s", got)
	}
	if m := IptablesMissing(allPorts(), "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n"); len(m) != 0 {
		t.Errorf("open: %v", m)
	}
	missing, table, chain := NftMissing(allPorts(), nftRuleset)
	if len(missing) != 1 || missing[0].Port != 7781 || table != "inet filter" || chain != "input" {
		t.Fatalf("nft: %v %s %s", missing, table, chain)
	}
	hint := RawHint(missing, table, chain, "")
	if !strings.Contains(hint, "sudo iptables -I INPUT -p udp -m multiport --dports 7781 -j ACCEPT") ||
		!strings.Contains(hint, "sudo nft add rule inet filter input udp dport { 7781 } accept") || strings.Contains(hint, "-p tcp") {
		t.Errorf("hint %s", hint)
	}
	if m, _, _ := NftMissing(allPorts(), "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t}\n}\n"); len(m) != 0 {
		t.Errorf("nft open: %v", m)
	}
	hint = RawHint(IptablesMissing(allPorts(), iptablesFedora), "", "", "")
	for _, want := range []string{"-p tcp -m multiport --dports 7782,7783,7784,7785 -j ACCEPT", "-p udp -m multiport --dports 7780,7781 -j ACCEPT",
		"nft add rule inet filter input tcp dport { 7782, 7783, 7784, 7785 } accept"} {
		if !strings.Contains(hint, want) {
			t.Errorf("no %q in %s", want, hint)
		}
	}
	if h := NeedsRootHint(allPorts()); !strings.Contains(h, "needs root") || !strings.Contains(h, "UDP 7780,7781") {
		t.Errorf("needs root: %s", h)
	}
}

func TestCheckNeverPanics(t *testing.T) {
	Check(allPorts(), []Range{{Proto: "udp", Min: 9000, Max: 9999}})
}
