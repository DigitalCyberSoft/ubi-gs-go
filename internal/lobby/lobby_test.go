package lobby_test

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/h5"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/proxy"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/server"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/srp"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

const (
	game      = "HEROES_657d2c2ebadc6a1d"
	gsVersion = "HEROES_c83663d1c69a2024"
)

type player struct {
	*gsclient.Client
	t    *testing.T
	ip   string
	name string
}

func roomInfo(t *testing.T) []byte {
	var s string
	testvec.Get(t, testvec.Load(t), "room_info_input", &s)
	return testvec.Hex(t, s)
}

// join logs a player in at the router (an account and session) and into the Casual lobby.
func join(t *testing.T, s *testserver.Server, ip, name, password string) *player {
	t.Helper()
	if _, err := s.Accounts().Login(name, password); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Accounts().Login(name, password)
	s.Accounts().BindSession(name, ip, a)
	c, err := gsclient.New(ip, s.Addr(env.PortLobby), gsm.PartyServer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	p := &player{Client: c, t: t, ip: ip, name: name}
	p.Send(gsm.LOBBYSERVERLOGIN, dl.S(name), dl.S("1"), dl.S("192.168.0.41"), dl.S("255.255.255.0"), dl.S("0"))
	p.lobby("23", dl.S("1"), dl.S(""), dl.S("384"))
	p.lobby("9", dl.S("1"), dl.S("384"))
	return p
}

func (p *player) lobby(sub string, args ...dl.Value) {
	if err := p.Send(gsm.LOBBY_MSG, dl.S(sub), dl.L(args...)); err != nil {
		p.t.Fatal(err)
	}
}

// msgs returns the LOBBY_MSG payloads received within a moment.
func (p *player) msgs() []dl.List {
	var out []dl.List
	for _, m := range p.All(300 * time.Millisecond) {
		out = append(out, m.Data)
	}
	return out
}

func notifs(l []dl.List, sub string) []dl.List {
	var out []dl.List
	for _, m := range l {
		if s, _ := m.Str(0); s == sub {
			out = append(out, m)
		}
	}
	return out
}

func (p *player) createRoom() string {
	p.msgs()
	p.lobby("12", dl.S("1"), dl.S("alice's Game"), dl.S(game), dl.S("7"), dl.S("2"), dl.S("0"), dl.B(roomInfo(p.t)),
		dl.S(""), dl.S(""), dl.S(gsVersion), dl.B(nil))
	for _, m := range p.msgs() {
		sub, _ := m.List(1)
		if r, _ := m.Str(0); r == "38" && sub[0].String() == "'12'" {
			ids, _ := sub.List(1)
			id, _ := ids.Str(0)
			p.lobby("24", dl.S(id), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
			return id
		}
	}
	p.t.Fatal("no CREATE_ROOM reply")
	return ""
}

func start(t *testing.T, edit func(*server.Config)) *testserver.Server {
	testserver.NeedLoopbackAliases(t)
	return testserver.Start(t, edit)
}

func TestMembersWithoutAddresses(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	got := alice.msgs()
	if len(got) == 0 || got[len(got)-1].String() != "['53', ['1', '384', [], [], [['alice', '0', '127.0.0.2', '192.168.0.41', b'', ['1'], '-1', '0']]]]" {
		t.Fatalf("alice's own entry: %v", got)
	}
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	members := notifs(bob.msgs(), "53")[0]
	if !strings.Contains(members.String(), "['alice', '0', '0.0.0.0', '0.0.0.0', b'', ['1'], '-1', '0']") {
		t.Fatalf("lobby-wide member list shows an address: %s", members)
	}
	if got := alice.msgs(); len(got) != 1 || got[0].String() != "['50', ['bob', '0', '1', '0.0.0.0', '0.0.0.0', b'', '0']]" {
		t.Fatalf("MEMBER_JOIN: %v", got)
	}
}

func TestRoomFlow(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	alice.msgs()
	bob.msgs()
	room := alice.createRoom()
	// the lobby sees the room without anyone's address
	ng := notifs(bob.msgs(), "54")
	if len(ng) != 1 {
		t.Fatalf("NEW_GROUP: %v", ng)
	}
	data, _ := ng[0].List(1)
	if name, _ := data.Str(1); name != "alice's Game" {
		t.Fatalf("room %s", data)
	}
	if ip, _ := data.Str(18); ip != "0.0.0.0" {
		t.Fatalf("room address %q in the lobby", ip)
	}
	alice.msgs()

	// the host adds itself to the room info, with its addresses
	info, _ := h5.DeserializeRoomInfo(roomInfo(t))
	info.HostIP = h5.SockAddr{Family: 2, Port: 8888, IP: [4]byte{127, 0, 0, 2}}
	info.PlayerInfos = append(info.PlayerInfos, &h5.PlayerInfo{Username: []byte("alice"),
		ExtIP: h5.SockAddr{Family: 2, Port: 8888, IP: [4]byte{127, 0, 0, 2}}, LocalPort: 8888, LocalIP: [4]byte{192, 168, 0, 41}})
	alice.lobby("31", dl.S(room), dl.S("64"), dl.B(info.Serialize()))
	upd := notifs(bob.msgs(), "53")
	if len(upd) != 1 {
		t.Fatalf("room update: %v", upd)
	}
	d, _ := upd[0].List(1)
	roomData, _ := d.List(2)
	gi, _ := roomData.Bin(10)
	seen, _ := h5.DeserializeRoomInfo(gi)
	if seen.HostIP.IP != [4]byte{} || seen.PlayerInfos[0].ExtIP.IP != [4]byte{} || seen.PlayerInfos[0].LocalIP != [4]byte{} {
		t.Fatalf("room info shows addresses outside the room: %+v", seen.PlayerInfos[0])
	}
	alice.msgs()
	// a joiner that isn't the host can't change the room
	bob.lobby("31", dl.S(room), dl.S("8"), dl.S("4"))
	if got := bob.msgs(); len(got) != 0 {
		t.Fatalf("a player changed someone else's room: %v", got)
	}

	// bob joins: GROUP_INFO with the room, the reply, then the members
	bob.lobby("24", dl.S(room), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	got := bob.msgs()
	var order []string
	for _, m := range got {
		s, _ := m.Str(0)
		order = append(order, s)
	}
	if strings.Join(order, " ") != "53 38 50 50" {
		t.Fatalf("join order %v", order)
	}
	d, _ = got[0].List(1)
	roomData, _ = d.List(2)
	gi, _ = roomData.Bin(10)
	seen, _ = h5.DeserializeRoomInfo(gi)
	if seen.HostIP.Addr().String() != "127.0.0.2" || seen.PlayerInfos[0].LocalIP != [4]byte{192, 168, 0, 41} {
		t.Fatal("a room member doesn't get the host's addresses")
	}
	if got[2].String()[:len("['50', ['alice', '0', '"+room+"', '127.0.0.2', '192.168.0.41'")] != "['50', ['alice', '0', '"+room+"', '127.0.0.2', '192.168.0.41'" {
		t.Fatalf("member data in the room: %s", got[2])
	}
	if a := notifs(alice.msgs(), "50"); len(a) != 1 || !strings.HasPrefix(a[0].String(), "['50', ['bob', '0', '"+room+"', '127.0.0.3', '192.168.0.41'") {
		t.Fatalf("alice gets bob: %v", a)
	}

	// match start
	alice.lobby("15", dl.S(room))
	alice.lobby("33", dl.S(room), dl.B(nil), dl.S("0"), dl.S(""))
	want := "['56', ['" + room + "', b'', '0', '127.0.0.2', '192.168.0.41']]"
	for _, p := range []*player{alice, bob} {
		started := notifs(p.msgs(), "56")
		if len(started) != 1 || started[0].String() != want {
			t.Fatalf("%s GAME_STARTED: %v", p.name, started)
		}
	}
	for _, sub := range []string{"34", "35", "44", "70"} {
		bob.lobby(sub, dl.S(room))
	}
	if got := bob.msgs(); len(got) != 0 {
		t.Fatalf("notifications answered: %v", got)
	}

	// bob leaves, then the host: the room goes
	bob.lobby("8", dl.S(room))
	if got := bob.msgs(); len(got) == 0 || got[len(got)-1].String() != "['38', ['8', ['"+room+"']]]" {
		t.Fatalf("leave: %v", got)
	}
	if l := notifs(alice.msgs(), "51"); len(l) != 1 || l[0].String() != "['51', ['bob', '"+room+"']]" {
		t.Fatalf("MEMBER_LEAVE: %v", l)
	}
	alice.Close()
	if got := bob.msgs(); len(got) != 2 || got[0].String() != "['55', ['"+room+"']]" || got[1].String() != "['51', ['alice', '1']]" {
		t.Fatalf("host gone: %v", got)
	}
}

func TestOwnNameIsTyped(t *testing.T) {
	s := start(t, nil)
	join(t, s, "127.0.0.2", "alice", "one")
	second := join(t, s, "127.0.0.3", "alice", "two")
	members := notifs(second.msgs(), "53")[0].String()
	// the game knows itself by the typed name; others see the account name
	if !strings.Contains(members, "['alice', '0', '0.0.0.0'") || !strings.Contains(members, "['alice', '0', '127.0.0.3'") {
		t.Fatalf("members: %s", members)
	}
	third := join(t, s, "127.0.0.4", "carol", "pw")
	if members := notifs(third.msgs(), "53")[0].String(); !strings.Contains(members, "'alice-1'") {
		t.Fatalf("others don't see alice-1: %s", members)
	}
}

func values(result string) dl.Value {
	v := make([]string, 22)
	for i := range v {
		v[i] = "0"
	}
	v[0], v[1], v[16], v[17] = result, "0", "65536", "87"
	return dl.Strs(v...)
}

func TestRatedMatch(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	alice.lobby("23", dl.S("2"), dl.S(""), dl.S("384"))
	bob.lobby("23", dl.S("2"), dl.S(""), dl.S("384"))
	alice.lobby("12", dl.S("2"), dl.S("alice's Game"), dl.S(game), dl.S("1"), dl.S("2"), dl.S("0"), dl.B(roomInfo(t)),
		dl.S(""), dl.S(""), dl.S(gsVersion), dl.B(nil))
	alice.msgs()
	room := strconv.Itoa(1000)
	for _, p := range []*player{alice, bob} {
		p.lobby("24", dl.S(room), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	}
	alice.msgs()
	bob.msgs()
	alice.lobby("17", dl.S(room), dl.S("1"), dl.S("0"))
	started := notifs(bob.msgs(), "62")
	if len(started) != 1 || started[0].String() != "['62', ['"+room+"', '1']]" {
		t.Fatalf("MATCH_STARTED %v", started)
	}
	alice.msgs()
	// both submit both players' values: alice won
	for _, p := range []*player{alice, bob} {
		p.lobby("30", dl.S("1"), dl.S("0"), dl.L(dl.S("alice"), dl.S("21"), dl.S("22"), dl.S("0"), values("1")),
			dl.L(dl.S("bob"), dl.S("21"), dl.S("22"), dl.S("0"), values("0")))
		if got := p.msgs(); len(got) != 1 || got[0].String() != "['38', ['30', ['1']]]" {
			t.Fatalf("SUBMIT_MATCH reply %v", got)
		}
	}
	alice.lobby("45", dl.S(room))
	final := notifs(bob.msgs(), "71")
	if len(final) != 1 || !strings.HasPrefix(final[0].String(), "['71', ['1', '38', [['alice', ['1'") {
		t.Fatalf("FINAL_MATCH_RESULTS %v", final)
	}
	key := proxy.LadderKey(game, "1")
	a, _ := s.Accounts().Find("alice")
	b, _ := s.Accounts().Find("bob")
	as, _ := s.Accounts().LadderStats(*a, key)
	bs, _ := s.Accounts().LadderStats(*b, key)
	if as["RATING"] != 1516 || bs["RATING"] != 1484 || as["WINS"] != 1 || bs["LOSSES"] != 1 || as["TOT_TIME_PLAYED"] != 87 ||
		as["AVERAGE_HERO_LEVEL"] != 65536 || as["W_HEAVEN"] != 1 || bs["L_HEAVEN"] != 1 || as["CUR_WINS_STREAK"] != 1 {
		t.Fatalf("ladder: alice %v bob %v", as, bs)
	}
}

func TestDisagreementSettledByTheHost(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	alice.createRoom()
	bob.lobby("24", dl.S("1000"), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	bob.msgs()
	// the match exists before anyone submits (the connections are separate: a submission arriving first
	// was dropped, and alice's report then counted alone)
	alice.lobby("17", dl.S("1000"), dl.S("1"), dl.S("0"))
	alice.msgs()
	// each claims the win
	alice.lobby("30", dl.S("1"), dl.S("0"), dl.L(dl.S("alice"), dl.S("21"), dl.S("22"), dl.S("0"), values("1")))
	bob.lobby("30", dl.S("1"), dl.S("0"), dl.L(dl.S("alice"), dl.S("21"), dl.S("22"), dl.S("0"), values("0")))
	bob.msgs() // the reply: bob's submission is in
	alice.lobby("45", dl.S("1000"))
	alice.msgs()
	// the host finished the match: its report (alice won) counts
	a, _ := s.Accounts().Find("alice")
	if st, _ := s.Accounts().LadderStats(*a, proxy.LadderKey(game, "1")); st["WINS"] != 1 {
		t.Fatalf("the host's report didn't settle the result: %v", st)
	}
}

func TestBadRequestsKeepThePlayer(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	alice.msgs()
	alice.lobby("99", dl.S("1"))
	alice.lobby("24", dl.S("4242"))
	alice.lobby("12", dl.S("1"))
	alice.Send(gsm.STILLALIVE)
	if got := alice.All(300 * time.Millisecond); len(got) != 1 || got[0].Header.Type != gsm.STILLALIVE {
		t.Fatalf("after bad requests: %v", got)
	}
}

// natPing registers a game port with the NAT service as the game does: SYN, address request, ping.
func natPing(t *testing.T, s *testserver.Server, ip string, gamePort *net.UDPConn) netip.AddrPort {
	t.Helper()
	natAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s.Addr(env.PortNAT)))
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	all := testvec.Load(t)
	var syn, msg string
	testvec.Get(t, all, "srp_syn", &syn)
	testvec.Get(t, all, "srp_msg", &msg)
	buf := make([]byte, 2048)
	c.WriteToUDP(testvec.Hex(t, syn), natAddr)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	c.WriteToUDP(testvec.Hex(t, msg), natAddr)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	seg, err := srp.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	args, _ := seg.Msg.Data.List(1)
	idS, _ := args.Str(1)
	id, _ := strconv.ParseInt(idS, 10, 32)
	gamePort.WriteToUDP(binary.BigEndian.AppendUint32(nil, uint32(int32(id))), natAddr)
	n, _, err = c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	seg, _ = srp.Parse(buf[:n])
	args, _ = seg.Msg.Data.List(1)
	ipS, _ := args.Str(1)
	portS, _ := args.Str(2)
	v, _ := strconv.ParseInt(ipS, 10, 32)
	port, _ := strconv.Atoi(portS)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, uint32(int32(v))))), uint16(port))
}

func TestRelayMode(t *testing.T) {
	s := start(t, func(c *server.Config) { c.Relay = true })
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	ga, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	gb, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.3")})
	defer ga.Close()
	defer gb.Close()
	relayA := natPing(t, s, "127.0.0.2", ga)
	relayB := natPing(t, s, "127.0.0.3", gb)
	if relayA.Addr().String() != "127.0.0.1" || int(relayA.Port()) < s.Config.RelayMin || relayA == relayB {
		t.Fatalf("NAT told %s and %s", relayA, relayB)
	}
	// the games advertise what the NAT service told them
	pi := func(name string, a netip.AddrPort) []byte {
		p := &h5.PlayerInfo{Username: []byte(name), ExtIP: h5.SockAddr{Family: 2, Port: a.Port(), IP: a.Addr().As4()},
			LocalPort: 8888, LocalIP: [4]byte{192, 168, 0, 41}, Int38: 1500}
		return p.Serialize()
	}
	alice.lobby("42", dl.B(pi("alice", relayA)))
	bob.lobby("42", dl.B(pi("bob", relayB)))
	room := alice.createRoom()
	alice.msgs()
	bob.msgs()
	bob.lobby("24", dl.S(room), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	for _, m := range bob.msgs() {
		// bob's own entry may show his own addresses
		text, _, _ := strings.Cut(m.String(), "['bob'")
		if strings.Contains(text, "127.0.0.2") || strings.Contains(text, "192.168.0.41") {
			t.Fatalf("bob sees alice's address: %s", text)
		}
	}
	// the host's GAME_READY data is its room info, with its own private address in its entry
	info, _ := h5.DeserializeRoomInfo(roomInfo(t))
	info.HostIP = h5.SockAddr{Family: 2, Port: relayA.Port(), IP: relayA.Addr().As4()}
	host, _ := h5.DeserializePlayerInfo(pi("alice", relayA))
	host.LocalIP, host.LocalPort = [4]byte{127, 0, 0, 2}, 8888
	info.PlayerInfos = []*h5.PlayerInfo{host}
	alice.lobby("33", dl.S(room), dl.B(info.Serialize()), dl.S("8888"), dl.S(""))
	started := notifs(bob.msgs(), "56")
	if len(started) != 1 {
		t.Fatalf("GAME_STARTED in relay mode: %v", started)
	}
	args, _ := started[0].List(1)
	if got := dl.List(args[2:]).String(); got != "['"+strconv.Itoa(int(relayA.Port()))+"', '127.0.0.1', '127.0.0.1']" {
		t.Fatalf("GAME_STARTED address: %s", got)
	}
	data, _ := args.Bin(1)
	seen, err := h5.DeserializeRoomInfo(data)
	if err != nil || seen.PlayerInfos[0].LocalIP != relayA.Addr().As4() || seen.PlayerInfos[0].LocalPort != relayA.Port() ||
		seen.HostIP.Addr() != relayA.Addr() || seen.HostIP.Port != relayA.Port() {
		t.Fatalf("GAME_STARTED data shows real addresses: %+v %v", seen, err)
	}
	// traffic: bob -> alice's relay port arrives at alice from bob's relay port
	toA := net.UDPAddrFromAddrPort(relayA)
	gb.WriteToUDP([]byte("hello alice"), toA)
	buf := make([]byte, 100)
	ga.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := ga.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "hello alice" || from != relayB {
		t.Fatalf("relayed %q from %s (%v), want from %s", buf[:n], from, err, relayB)
	}
	ga.WriteToUDP([]byte("hi bob"), net.UDPAddrFromAddrPort(relayB))
	gb.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err = gb.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "hi bob" || from != relayA {
		t.Fatalf("relayed back %q from %s (%v)", buf[:n], from, err)
	}
	// a stranger can't use the relay
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.9")})
	defer stranger.Close()
	stranger.WriteToUDP([]byte("spoof"), toA)
	ga.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := ga.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatal("a stranger's datagram was relayed")
	}
	if tot := s.Relay().Totals(); tot.Packets != 2 || tot.Dropped != 1 {
		t.Fatalf("relay totals %+v", tot)
	}
}
