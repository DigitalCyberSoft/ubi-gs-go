// Package firewall checks, best effort and read-only, that the host firewall lets players reach the
// server's ports. It only warns; it never changes anything.
//
// Windows: Windows Defender Firewall rules (netsh advfirewall), where a listening program can still be
// blocked. Linux: a short hint when firewalld, ufw or plain iptables/nftables rules may keep ports closed.
package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ports"
)

// Range is a range of ports for a firewall rule (e.g. the relay's).
type Range struct {
	Proto    string
	Min, Max int
}

func run(name string, args ...string) (string, string, int, bool) {
	cmd := exec.Command(name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return "", "", -1, false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			return "", "", -1, false
		}
		return stdout.String(), stderr.String(), code, true
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		return "", "", -1, false
	}
}

func output(name string, args ...string) (string, bool) {
	out, _, code, ok := run(name, args...)
	return out, ok && code == 0
}

func portList(list []int) string {
	seen := map[int]bool{}
	var u []int
	for _, p := range list {
		if !seen[p] {
			seen[p] = true
			u = append(u, p)
		}
	}
	sort.Ints(u)
	s := make([]string, len(u))
	for i, p := range u {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

// PortMatches reports whether a port spec (`Any`, `80`, `7777-7785`, `80,443`) covers the port.
func PortMatches(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "any") {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := strconv.Atoi(lo)
			h, e2 := strconv.Atoi(hi)
			if e1 == nil && e2 == nil && l <= port && port <= h {
				return true
			}
		} else if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

// --- Windows ---------------------------------------------------------------

var netshField = regexp.MustCompile(`^([A-Za-z][A-Za-z ]*?):\s*(.*)$`)

// ParseNetshRules reads `netsh advfirewall firewall show rule name=all dir=in verbose` output into rules
// of lowercase field names.
func ParseNetshRules(out string) []map[string]string {
	var rules []map[string]string
	var rule map[string]string
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		if strings.HasPrefix(line, "---") {
			continue
		}
		m := netshField.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
		if key == "rule name" {
			rule = map[string]string{"rule name": value}
			rules = append(rules, rule)
		} else if rule != nil {
			rule[key] = value
		}
	}
	return rules
}

func get(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func sameProgram(ruleProgram string, programs []string) bool {
	path := os.ExpandEnv(strings.Trim(strings.TrimSpace(ruleProgram), `"`))
	for _, p := range programs {
		if strings.EqualFold(filepath.Clean(path), filepath.Clean(p)) {
			return true
		}
	}
	return false
}

func ruleCovers(rule map[string]string, proto string, port int, programs []string) bool {
	if !strings.EqualFold(get(rule, "enabled", ""), "yes") || !strings.EqualFold(get(rule, "direction", "in"), "in") {
		return false
	}
	if p := strings.ToLower(get(rule, "protocol", "any")); p != "any" && p != proto {
		return false
	}
	if !PortMatches(get(rule, "localport", "Any"), port) {
		return false
	}
	program := get(rule, "program", "Any")
	return strings.EqualFold(program, "any") || sameProgram(program, programs)
}

// Blocked is a port the firewall may block, and why.
type Blocked struct {
	ports.Port
	Reason string
}

// WindowsBlocked returns the ports no enabled inbound rule allows, or that a rule blocks.
func WindowsBlocked(list []ports.Port, rules []map[string]string, programs []string) []Blocked {
	var out []Blocked
	for _, p := range list {
		var blockers []string
		allowed := false
		for _, r := range rules {
			if !ruleCovers(r, p.Proto, p.Port, programs) {
				continue
			}
			switch strings.ToLower(get(r, "action", "")) {
			case "block":
				blockers = append(blockers, r["rule name"])
			case "allow":
				allowed = true
			}
		}
		if len(blockers) > 0 {
			sort.Strings(blockers)
			out = append(out, Blocked{p, fmt.Sprintf(`blocked by rule "%s"`, strings.Join(dedupe(blockers), ", "))})
		} else if !allowed {
			out = append(out, Blocked{p, "no rule allows it"})
		}
	}
	return out
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

var stateOff = regexp.MustCompile(`(?mi)^State\s+OFF\s*$`)

// WindowsAddRuleCommands are netsh commands that open the ports, one per protocol.
func WindowsAddRuleCommands(list []ports.Port, ranges []Range) []string {
	var cmds []string
	for _, proto := range []string{"tcp", "udp"} {
		var nums []int
		for _, p := range list {
			if p.Proto == proto {
				nums = append(nums, p.Port)
			}
		}
		spec := portList(nums)
		for _, r := range ranges {
			if r.Proto == proto {
				if spec != "" {
					spec += ","
				}
				spec += fmt.Sprintf("%d-%d", r.Min, r.Max)
			}
		}
		if spec != "" {
			P := strings.ToUpper(proto)
			cmds = append(cmds, fmt.Sprintf(`netsh advfirewall firewall add rule name="ubi-gs %s" dir=in action=allow protocol=%s localport=%s`, P, P, spec))
		}
	}
	return cmds
}

// WindowsWarning is the warning for Windows, or "" if the firewall lets all the ports in.
func WindowsWarning(list []ports.Port, ranges []Range, rulesOut, stateOut string, programs []string) string {
	if stateOut != "" && stateOff.MatchString(stateOut) {
		return ""
	}
	rules := ParseNetshRules(rulesOut)
	var blocked []Blocked
	var detail []string
	var head string
	if len(rules) > 0 {
		blocked = WindowsBlocked(list, rules, programs)
		if len(blocked) == 0 {
			return ""
		}
		for _, b := range blocked {
			detail = append(detail, fmt.Sprintf("  %s %d (%s): %s", strings.ToUpper(b.Proto), b.Port.Port, b.Service, b.Reason))
		}
		head = "WARNING: Windows Defender Firewall may block players from reaching these ports:"
	} else {
		for _, p := range list {
			blocked = append(blocked, Blocked{p, ""})
		}
		for _, proto := range []string{"tcp", "udp"} {
			var nums []int
			for _, p := range list {
				if p.Proto == proto {
					nums = append(nums, p.Port)
				}
			}
			if len(nums) > 0 {
				detail = append(detail, fmt.Sprintf("  %s: %s", strings.ToUpper(proto), portList(nums)))
			}
		}
		head = "WARNING: could not read the Windows Defender Firewall rules; make sure these ports are open to players:"
	}
	line := strings.Repeat("=", 78)
	lines := append([]string{"", line, head}, detail...)
	lines = append(lines, "The server is running, but other players can't connect until the firewall lets them in.",
		"To open the ports, run in a command prompt started as administrator:")
	var bl []ports.Port
	blockedByRule := false
	for _, b := range blocked {
		bl = append(bl, b.Port)
		blockedByRule = blockedByRule || strings.HasPrefix(b.Reason, "blocked by rule")
	}
	for _, c := range WindowsAddRuleCommands(bl, ranges) {
		lines = append(lines, "  "+c)
	}
	if blockedByRule {
		lines = append(lines, `and disable the blocking rules above (Windows creates them when its "allow access" prompt is cancelled).`)
	}
	lines = append(lines, line, "")
	return strings.Join(lines, "\n")
}

func checkWindows(list []ports.Port, ranges []Range) string {
	rules, _ := output("netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in", "verbose")
	state, _ := output("netsh", "advfirewall", "show", "currentprofile", "state")
	var programs []string
	if exe, err := os.Executable(); err == nil {
		programs = append(programs, exe)
	}
	return WindowsWarning(list, ranges, rules, state, programs)
}

// --- Linux: firewalld and ufw ---------------------------------------------

func active(unit string) bool {
	out, ok := output("systemctl", "is-active", unit)
	return ok && strings.TrimSpace(out) == "active"
}

// FirewalldMissing returns the ports firewalld doesn't open (--list-ports, or the http service for 80/tcp).
func FirewalldMissing(list []ports.Port, openPorts, services string) []ports.Port {
	opened := strings.Fields(openPorts)
	svc := map[string]bool{}
	for _, s := range strings.Fields(services) {
		svc[s] = true
	}
	var missing []ports.Port
outer:
	for _, p := range list {
		for _, o := range opened {
			if o == fmt.Sprintf("%d/%s", p.Port, p.Proto) {
				continue outer
			}
			if spec, proto, ok := strings.Cut(o, "/"); ok && proto == p.Proto && strings.Contains(spec, "-") && PortMatches(spec, p.Port) {
				continue outer
			}
		}
		if p.Port == 80 && p.Proto == "tcp" && svc["http"] {
			continue
		}
		missing = append(missing, p)
	}
	return missing
}

// UfwMissing returns the ports `ufw status` doesn't show as allowed.
func UfwMissing(list []ports.Port, status string) []ports.Port {
	var missing []ports.Port
	for _, p := range list {
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^%d(/%s)?\s+(\(v6\)\s+)?ALLOW`, p.Port, p.Proto))
		if !re.MatchString(status) {
			missing = append(missing, p)
		}
	}
	return missing
}

// LinuxHint is the one-line hint for firewalld or ufw.
func LinuxHint(missing []ports.Port, tool string) string {
	if len(missing) == 0 {
		return ""
	}
	var spec, adds, ufw []string
	for _, p := range missing {
		spec = append(spec, fmt.Sprintf("%d/%s", p.Port, p.Proto))
		adds = append(adds, fmt.Sprintf("--add-port=%d/%s", p.Port, p.Proto))
		ufw = append(ufw, fmt.Sprintf("sudo ufw allow %d/%s", p.Port, p.Proto))
	}
	cmd := strings.Join(ufw, "; ")
	if tool == "firewalld" {
		cmd = "sudo firewall-cmd --permanent " + strings.Join(adds, " ") + " && sudo firewall-cmd --reload"
	}
	return fmt.Sprintf("Note: %s is active and may block players from reaching %s. To open them: %s", tool, strings.Join(spec, " "), cmd)
}

func checkLinux(list []ports.Port) string {
	if active("firewalld") {
		listed, ok := output("firewall-cmd", "--list-ports")
		if !ok {
			return LinuxHint(list, "firewalld")
		}
		services, _ := output("firewall-cmd", "--list-services")
		return LinuxHint(FirewalldMissing(list, listed, services), "firewalld")
	}
	if active("ufw") {
		status, ok := output("ufw", "status")
		// reading the rules needs root; then just mention the ports
		if !ok || status == "" {
			return LinuxHint(list, "ufw")
		}
		return LinuxHint(UfwMissing(list, status), "ufw")
	}
	return checkRawLinux(list)
}

// --- Linux: plain iptables / nftables ---------------------------------------

// Saved rulesets, often readable without root.
var (
	IptablesSaved = []string{"/etc/sysconfig/iptables", "/etc/iptables/rules.v4"}
	NftSaved      = []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"}
)

var needsRoot = regexp.MustCompile(`(?i)permission denied|not permitted|must be root|you must be root`)

type iptChain struct {
	policy string
	rules  [][]string
}

// ParseIptables reads `iptables -S` or iptables-save output.
func ParseIptables(out string) map[string]*iptChain {
	chains := map[string]*iptChain{}
	chain := func(name string) *iptChain {
		if chains[name] == nil {
			chains[name] = &iptChain{}
		}
		return chains[name]
	}
	for _, line := range strings.Split(out, "\n") {
		w := strings.Fields(line)
		if len(w) == 0 {
			continue
		}
		switch {
		case w[0] == "-P" && len(w) >= 3:
			chain(w[1]).policy = strings.ToUpper(w[2])
		case w[0] == "-N" && len(w) >= 2:
			chain(w[1])
		case strings.HasPrefix(w[0], ":") && len(w) >= 2:
			// iptables-save: ":INPUT DROP [0:0]", user chains have "-"
			p := strings.ToUpper(w[1])
			if p == "-" {
				p = ""
			}
			chain(w[0][1:]).policy = p
		case w[0] == "-A" && len(w) >= 2:
			c := chain(w[1])
			c.rules = append(c.rules, w[2:])
		}
	}
	return chains
}

func opt(args []string, names ...string) (string, bool) {
	for i, w := range args {
		for _, n := range names {
			if w == n && i+1 < len(args) {
				return args[i+1], true
			}
		}
	}
	return "", false
}

var qualifiers = map[string]bool{"-s": true, "--source": true, "-i": true, "--in-interface": true, "--state": true,
	"--ctstate": true, "--src-range": true, "--sport": true, "--sports": true, "--source-port": true, "--mac-source": true}

func qualified(args []string) bool {
	for _, w := range args {
		if qualifiers[w] {
			return true
		}
	}
	return false
}

var portOpts = []string{"--dport", "--destination-port", "--dports", "--destination-ports"}

func iptAccepts(args []string, proto string, port int) bool {
	if t, _ := opt(args, "-j", "--jump"); t != "ACCEPT" {
		return false
	}
	if p, ok := opt(args, "-p", "--protocol"); ok && p != "all" && p != proto {
		return false
	}
	if spec, ok := opt(args, portOpts...); ok {
		return PortMatches(strings.ReplaceAll(spec, ":", "-"), port)
	}
	// no port match: only an otherwise unconditional ACCEPT lets the port in
	return !qualified(args)
}

func iptVerdict(chains map[string]*iptChain, name, proto string, port, depth int) string {
	c := chains[name]
	if depth > 8 || c == nil {
		return ""
	}
	for _, args := range c.rules {
		if iptAccepts(args, proto, port) {
			return "accept"
		}
		target, _ := opt(args, "-j", "--jump", "-g", "--goto")
		p, hasP := opt(args, "-p", "--protocol")
		applies := (!hasP || p == "all" || p == proto) && !qualified(args)
		if spec, ok := opt(args, portOpts...); ok {
			applies = applies && PortMatches(strings.ReplaceAll(spec, ":", "-"), port)
		}
		if (target == "DROP" || target == "REJECT") && applies {
			return "drop"
		}
		if chains[target] != nil {
			if v := iptVerdict(chains, target, proto, port, depth+1); v != "" {
				return v
			}
		}
	}
	return ""
}

// IptablesMissing returns the ports the INPUT chain would drop (DROP/REJECT policy or a final catch-all).
func IptablesMissing(list []ports.Port, out string) []ports.Port {
	chains := ParseIptables(out)
	in := chains["INPUT"]
	if in == nil {
		return nil
	}
	var missing []ports.Port
	for _, p := range list {
		v := iptVerdict(chains, "INPUT", p.Proto, p.Port, 0)
		if v == "drop" || (v == "" && (in.policy == "DROP" || in.policy == "REJECT")) {
			missing = append(missing, p)
		}
	}
	return missing
}

type nftChain struct {
	table, name string
	input       bool
	policy      string
	rules       []string
}

var (
	nftTable     = regexp.MustCompile(`^table\s+(\w+)\s+(\S+)\s*\{`)
	nftChainRe   = regexp.MustCompile(`^chain\s+(\S+)\s*\{`)
	nftHook      = regexp.MustCompile(`\bhook\s+input\b`)
	nftPolicy    = regexp.MustCompile(`\bpolicy\s+(\w+)`)
	nftDport     = regexp.MustCompile(`\b(tcp|udp|th)\s+dport\s+(\{[^}]*\}|\S+)`)
	nftL4        = regexp.MustCompile(`\bl4proto\s+(\{[^}]*\}|\S+)`)
	nftQualifier = regexp.MustCompile(`\b(iif|iifname|saddr|ct\s+state|sport|ether|meta\s+mark)\b`)
	nftAccept    = regexp.MustCompile(`\baccept\b`)
	nftDrop      = regexp.MustCompile(`\b(drop|reject)\b`)
	nftJump      = regexp.MustCompile(`\b(jump|goto)\s+(\S+)`)
)

// ParseNft reads `nft list ruleset` or nftables.conf.
func ParseNft(out string) []*nftChain {
	var chains []*nftChain
	table := ""
	var cur *nftChain
	for _, raw := range strings.Split(out, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := nftTable.FindStringSubmatch(line); m != nil {
			table, cur = m[1]+" "+m[2], nil
			continue
		}
		if m := nftChainRe.FindStringSubmatch(line); m != nil && table != "" {
			cur = &nftChain{table: table, name: m[1]}
			chains = append(chains, cur)
			continue
		}
		if line == "}" {
			if cur != nil {
				cur = nil
			} else {
				table = ""
			}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "type ") {
			cur.input = nftHook.MatchString(line)
			if m := nftPolicy.FindStringSubmatch(line); m != nil {
				cur.policy = strings.ToLower(m[1])
			}
			continue
		}
		cur.rules = append(cur.rules, line)
	}
	return chains
}

func nftPorts(spec string) string {
	return strings.ReplaceAll(strings.Trim(strings.TrimSpace(spec), "{}"), " ", "")
}

func nftVerdict(chains []*nftChain, c *nftChain, proto string, port, depth int) string {
	if depth > 8 {
		return ""
	}
	for _, rule := range c.rules {
		ok := true
		if m := nftDport.FindStringSubmatch(rule); m != nil {
			if m[1] != "th" && m[1] != proto {
				ok = false
			} else if !PortMatches(nftPorts(m[2]), port) {
				ok = false
			}
		}
		if m := nftL4.FindStringSubmatch(rule); m != nil && !strings.Contains(m[1], proto) {
			ok = false
		}
		if !ok || nftQualifier.MatchString(rule) {
			continue
		}
		if nftAccept.MatchString(rule) {
			return "accept"
		}
		if nftDrop.MatchString(rule) {
			return "drop"
		}
		if m := nftJump.FindStringSubmatch(rule); m != nil {
			for _, t := range chains {
				if t.table == c.table && t.name == m[2] {
					if v := nftVerdict(chains, t, proto, port, depth+1); v != "" {
						return v
					}
				}
			}
		}
	}
	return ""
}

// NftMissing returns the ports an input-hook chain would drop, and the first such chain.
func NftMissing(list []ports.Port, out string) ([]ports.Port, string, string) {
	chains := ParseNft(out)
	var missing []ports.Port
	table, chain := "", ""
	for _, p := range list {
		for _, c := range chains {
			if !c.input {
				continue
			}
			v := nftVerdict(chains, c, p.Proto, p.Port, 0)
			if v == "drop" || (v == "" && c.policy == "drop") {
				missing = append(missing, p)
				if table == "" {
					table, chain = c.table, c.name
				}
				break
			}
		}
	}
	return missing, table, chain
}

// RawHint is the hint with iptables and nft commands that open the missing ports.
func RawHint(missing []ports.Port, table, chain, source string) string {
	if len(missing) == 0 {
		return ""
	}
	if table == "" {
		table, chain = "inet filter", "input"
	}
	var spec []string
	for _, p := range missing {
		spec = append(spec, fmt.Sprintf("%d/%s", p.Port, p.Proto))
	}
	lines := []string{fmt.Sprintf("Note: the firewall rules%s may block players from reaching %s. To open them, for example:", source, strings.Join(spec, " "))}
	for _, proto := range []string{"tcp", "udp"} {
		var nums []int
		for _, p := range missing {
			if p.Proto == proto {
				nums = append(nums, p.Port)
			}
		}
		if len(nums) == 0 {
			continue
		}
		list := portList(nums)
		lines = append(lines, fmt.Sprintf("  sudo iptables -I INPUT -p %s -m multiport --dports %s -j ACCEPT", proto, list))
		lines = append(lines, fmt.Sprintf("  sudo nft add rule %s %s %s dport { %s } accept", table, chain, proto, strings.ReplaceAll(list, ",", ", ")))
	}
	lines = append(lines, "  (and save them the way your distribution does, e.g. iptables-save or /etc/nftables.conf)")
	return strings.Join(lines, "\n")
}

// NeedsRootHint says the rules couldn't be read.
func NeedsRootHint(list []ports.Port) string {
	var tcp, udp []int
	for _, p := range list {
		if p.Proto == "tcp" {
			tcp = append(tcp, p.Port)
		} else {
			udp = append(udp, p.Port)
		}
	}
	var parts []string
	if len(tcp) > 0 {
		parts = append(parts, "TCP "+portList(tcp))
	}
	if len(udp) > 0 {
		parts = append(parts, "UDP "+portList(udp))
	}
	return fmt.Sprintf("Note: reading the iptables/nftables rules needs root, so the firewall was not checked. To check that players can reach %s, run: sudo iptables -S INPUT; sudo nft list ruleset",
		strings.Join(parts, " and "))
}

func checkRawLinux(list []ports.Port) string {
	locked := false
	if out, stderr, code, ok := run("iptables", "-S"); ok {
		if code == 0 {
			return RawHint(IptablesMissing(list, out), "", "", "")
		}
		locked = locked || needsRoot.MatchString(stderr)
	}
	if out, stderr, code, ok := run("nft", "list", "ruleset"); ok {
		if code == 0 {
			m, t, c := NftMissing(list, out)
			return RawHint(m, t, c, "")
		}
		locked = locked || needsRoot.MatchString(stderr)
	}
	for _, path := range IptablesSaved {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return RawHint(IptablesMissing(list, string(b)), "", "", " saved in "+path)
		}
	}
	for _, path := range NftSaved {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			m, t, c := NftMissing(list, string(b))
			return RawHint(m, t, c, " saved in "+path)
		}
	}
	if locked {
		return NeedsRootHint(list)
	}
	return ""
}

// Check returns the warning or hint for the ports, or "". It never fails.
func Check(list []ports.Port, ranges []Range) (text string) {
	defer func() {
		if r := recover(); r != nil {
			text = fmt.Sprintf("Note: could not check the firewall (%v); make sure the ports are open to players.", r)
		}
	}()
	switch runtime.GOOS {
	case "windows":
		return checkWindows(list, ranges)
	case "linux":
		// the relay range is checked by its first port
		all := append([]ports.Port(nil), list...)
		for _, r := range ranges {
			all = append(all, ports.Port{Service: "relay", Proto: r.Proto, Port: r.Min})
		}
		return checkLinux(all)
	}
	return ""
}
