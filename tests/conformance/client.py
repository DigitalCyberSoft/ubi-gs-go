#!/usr/bin/env python3
"""Black-box conformance client: drives a running ubi-gs (the Go binary) with the Python
implementation's own protocol modules, as two games would.

Usage: python3 client.py <path to the Python ubi-gs> <port offset> <gsconnect port>
The server must listen on 127.0.0.1 with the relay on and accept 127.0.0.2/127.0.0.3 as clients.
Exits 0 when every check passes; prints what failed otherwise.
"""
import os, socket, struct, sys, time, urllib.request

ref, OFFSET, GSCONNECT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [ref, os.path.join(ref, 'homm5')]
import blowfish, cdkm, gsm, ircm, pkc, srp, utils  # noqa: E402
from data import List  # noqa: E402

GAME, GS_VERSION = 'HEROES_657d2c2ebadc6a1d', 'HEROES_c83663d1c69a2024'
HOST = '127.0.0.1'
PORT = {name: port + OFFSET for name, port in
  dict(router=7777, irc=7779, cdkey=7780, nat=7781, router_wm=7782, proxy=7783, proxy_wm=7784, lobby=7785).items()}
ROOM_INFO = bytes.fromhex(
  "04080400000001d90200000208ffffffff0308ffffffff04240220000000000000000000000000000000000602000730"
  "61006c00690063006500270073002000470061006d00650008000902000a02000b02000c02000d08ffffffff0e080100"
  "00000f6602622f4d6170732f4d756c7469706c617965722f53342f53342e7864622378706f696e746572282f4164764d"
  "61704465736329132001080200000002100100000001000000140802000000150801000000161803080000000004080d"
  "00000017083c0001001802001920000000000000000000000000000000001a02001b5403080100000004080d00000001"
  "206175746f736176655f656e61626c65640214020800000000030430001c02001d087737aa291e08010000001f760272"
  "2f4d6170732f4d756c7469706c617965722f53342f6d61702d7461672e7864622378706f696e746572282f4164764d61"
  "704465736354616729200a676f616c352100250800000000260800000000270800000000280200000002000500")

checks = 0
def check(cond, what):
  global checks
  checks += 1
  if not cond:
    print(f'FAIL: {what}', flush=True)
    sys.exit(1)
  print(f'ok: {what}', flush=True)


class GS:
  """A game's GS connection, using the reference's message classes."""
  def __init__(self, src, service, receiver=gsm.SENDER_RECEIVER.R):
    self.sock = socket.create_connection((HOST, PORT[service]), timeout=5, source_address=(src, 0))
    self.receiver = receiver
    self.buf = b''
    self.bf_key = None

  def send(self, msg_type, data):
    header = gsm.GSMessageHeader.from_params(gsm.PROPERTY.GS, 1, msg_type, gsm.SENDER_RECEIVER.P, self.receiver)
    self.sock.sendall(bytes(gsm.GSMNotification(gsm.Message(None, header=header, dl=List(data)))))

  def send_encrypted(self, msg_type, data):
    enc = blowfish.Cipher(self.bf_key).encrypt(List(data).to_buf())
    header = gsm.GSMessageHeader.from_params(gsm.PROPERTY.GS_ENCRYPT, 1, msg_type, gsm.SENDER_RECEIVER.P, self.receiver)
    header.size = gsm.GSMSG_HEADER_SIZE + len(enc)
    self.sock.sendall(bytes(header) + enc)

  def recv(self, wait=3.0):
    """One message, or None."""
    end = time.monotonic() + wait
    while True:
      if len(self.buf) >= 6:
        size = (self.buf[0] << 16) + (self.buf[1] << 8) + self.buf[2]
        if len(self.buf) >= size:
          msg, self.buf = gsm.Message(None, in_buf=self.buf[:size]), self.buf[size:]
          return msg
      left = end - time.monotonic()
      if left <= 0:
        return None
      self.sock.settimeout(left)
      try:
        data = self.sock.recv(65536)
      except socket.timeout:
        return None
      if not data:
        return None
      self.buf += data

  def all(self, wait=0.4):
    out = []
    while True:
      m = self.recv(wait)
      if m is None:
        return out
      out.append(m)

  def request(self, msg_type, data):
    self.send(msg_type, data)
    return self.recv()

  def key_exchange(self):
    pub, priv = pkc.keygen()
    buf = bytes(pkc.RsaPublicKey.from_pubkey(pub))
    res = self.request(gsm.MESSAGE_TYPE.KEY_EXCHANGE, ['1', ['1', str(len(buf)), buf]])
    server_key = pkc.RsaPublicKey.from_buf(res.dl.lst[1][2]).to_pubkey()
    enc = pkc.encrypt(os.urandom(16), server_key)
    res = self.request(gsm.MESSAGE_TYPE.KEY_EXCHANGE, ['2', ['1', str(len(enc)), enc]])
    self.bf_key = pkc.decrypt(bytes(res.dl.lst[1][2]), priv)

  def close(self):
    self.sock.close()


def lobby_msgs(conn, wait=0.4):
  return [m.dl.lst for m in conn.all(wait) if m.header.type == gsm.MESSAGE_TYPE.LOBBY_MSG]


# --- gsconnect: servers.ini through an HTTP proxy, as the game's libcurl asks it -----------
opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{GSCONNECT}'}))
ini = opener.open(f'http://gsconnect.ubisoft.com/gsinit.php?dp={GAME}', timeout=5).read().decode()
check(f'RouterPort0={PORT["router"]}' in ini and 'RouterIP0=127.0.0.1' in ini and 'ServerID=' in ini, 'gsconnect serves servers.ini with the ports and a ServerID')

# --- CD key -----------------------------------------------------------------------------
def cdkey_request(msg_id, req_type, data):
  lst = [msg_id, str(req_type)] if data is None else [msg_id, str(req_type), '1', data]
  enc = cdkm.BLOWFISH.encrypt(List(lst).to_buf())
  return bytes([1]) + utils.write_u32_be(len(enc)) + enc

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(2)
udp.sendto(cdkey_request('6', 6, [bytes(20)]), (HOST, PORT['cdkey']))  # DISCONNECT_USER: no reply, no crash
for msg_id, t in [('1', 1), ('2', 2), ('3', 3), ('4', 4)]:
  udp.sendto(cdkey_request(msg_id, t, [b'x' * 16]), (HOST, PORT['cdkey']))
  res = cdkm.CDKeyMessage(udp.recv(2048))
  check(res.req_type.value == t and res.dl.lst[3][0] == '38', f'CD key {res.req_type.name} succeeds')

# --- router: key exchange, encrypted LOGIN, alice and alice-1 ------------------------------
def router_login(src, name, password):
  r = GS(src, 'router')
  r.key_exchange()
  r.send_encrypted(gsm.MESSAGE_TYPE.LOGIN, [name, password, GAME])
  res = r.recv()
  return r, res

alice_r, res = router_login('127.0.0.2', 'alice', 'one')
check(res.header.type == gsm.MESSAGE_TYPE.GSSUCCESS and res.dl.lst == [b'f'], 'alice logs in (RSA key exchange, Blowfish LOGIN)')
second_r, res = router_login('127.0.0.3', 'alice', 'two')
check(res.header.type == gsm.MESSAGE_TYPE.GSSUCCESS, 'a second alice with another password logs in')
bob_r, res = router_login('127.0.0.4', 'bob', 'pw')
_, res = router_login('127.0.0.5', 'a b', 'pw')
check(res.header.type == gsm.MESSAGE_TYPE.GSFAIL and res.dl.lst == [b'f', [(2).to_bytes(4, 'little')]], 'a malformed name is refused with USERNAME_MALFORMED')
res = alice_r.request(gsm.MESSAGE_TYPE.JOINWAITMODULE, [])
check(res.dl.lst[1] == ['127.0.0.1', utils.write_u32(PORT['router_wm'])], 'JOINWAITMODULE sends the wait module address')

def wait_module(src, typed):
  wm = GS(src, 'router_wm')
  wm.request(gsm.MESSAGE_TYPE.LOGINWAITMODULE, [typed])
  return wm

second_wm = wait_module('127.0.0.3', 'alice')
res = second_wm.request(gsm.MESSAGE_TYPE.PLAYERINFO, ['alice'])
check(res.dl.lst[1][:2] == ['alice-1', 'alice-1'], 'the second alice is alice-1')

# --- friends ----------------------------------------------------------------------------
alice_wm = wait_module('127.0.0.2', 'alice')
bob_wm = wait_module('127.0.0.4', 'bob')
for wm in (alice_wm, bob_wm):
  wm.send(gsm.MESSAGE_TYPE.LOGINFRIENDS, [bytes(4), bytes(4)])
  wm.all()
alice_wm.send(gsm.MESSAGE_TYPE.ADDFRIEND, ['bob', '', bytes(4)])
got = alice_wm.all()
check([(m.header.type, m.dl.lst) for m in got] == [(gsm.MESSAGE_TYPE.GSSUCCESS, [b'K', 'bob']),
  (gsm.MESSAGE_TYPE.UPDATEFRIEND, ['bob', bytes(4), '', bytes(4), bytes(4), ''])], 'a friend is added and shows online (status 0)')

# --- ladder ------------------------------------------------------------------------------
res = alice_wm.request(gsm.MESSAGE_TYPE.PROXY_HANDLER, ['1', ['ladderquery', '0', '0']])
check(res.dl.lst[0] == '38' and res.dl.lst[1][1][3][0][2] == str(PORT['proxy']), 'the ladder module is on the proxy')
proxy = GS('127.0.0.2', 'proxy')
proxy.request(gsm.MESSAGE_TYPE.LOGIN, ['alice', GAME])
res = proxy.request(gsm.MESSAGE_TYPE.JOINWAITMODULE, [])
check(res.dl.lst[1][1:] == ['127.0.0.1', str(PORT['proxy_wm'])], 'the proxy sends its wait module')
pwm = GS('127.0.0.2', 'proxy_wm')
pwm.request(gsm.MESSAGE_TYPE.LOGINWAITMODULE, ['alice'])
def ladder(name):
  res = pwm.request(gsm.MESSAGE_TYPE.PROXY_HANDLER, ['1281', '5', ['1', ['1', GAME, '1', '0', ['1', [name, '1']], [[], [], []]]]])
  code, seq, (result, (_, (_, _, columns, rows))) = res.dl.lst
  return code, seq, result, dict(zip([c[0] for c in columns], rows[0]))
code, seq, result, row = ladder('alice')
check((code, seq, result, row['RATING'], len(row)) == ('1281', '5', '38', '1500', 42), 'a ladder query returns 42 fields, rating 1500')

# --- NAT and relay -----------------------------------------------------------------------
def nat_address(src):
  game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  game.bind((src, 0))
  game.settimeout(2)
  conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  conn.bind((src, 0))
  conn.settimeout(2)
  syn = struct.pack('<HHHHHH', 0, 1, 8, 2 | 0x3040, 0, 0) + struct.pack('<HHHH', 10, 1, 0x1AB7, 0x218)
  conn.sendto(syn, (HOST, PORT['nat']))
  srp.SRPRequest(conn.recv(2048))
  header = gsm.GSMessageHeader.from_params(gsm.PROPERTY.GS, 1, gsm.MESSAGE_TYPE.NAT, gsm.SENDER_RECEIVER.UNK, gsm.SENDER_RECEIVER.S)
  nat_req = bytes(gsm.GSMNotification(gsm.Message(None, header=header, dl=List(['1', ['1', '', GAME, GS_VERSION]]))))
  conn.sendto(struct.pack('<HHHHHH', 0, 1, len(nat_req), 0x3040, 1, 0) + nat_req, (HOST, PORT['nat']))
  res = srp.SRPRequest(conn.recv(2048))
  ping_id = int(res.segment.msg.dl.lst[1][1])
  game.sendto(struct.pack('>i', ping_id), (HOST, PORT['nat']))
  res = srp.SRPRequest(conn.recv(2048))
  ip, port = int(res.segment.msg.dl.lst[1][1]), int(res.segment.msg.dl.lst[1][2])
  return game, socket.inet_ntoa(struct.pack('>i', ip)), port

game_a, ip_a, relay_a = nat_address('127.0.0.2')
game_b, ip_b, relay_b = nat_address('127.0.0.4')
check(ip_a == '127.0.0.1' and relay_a != relay_b and relay_a != game_a.getsockname()[1], 'NAT replies with relay addresses, not the real ones')

# --- lobby: two players, a room, the match start ----------------------------------------------
def lobby_join(src, name):
  c = GS(src, 'lobby', gsm.SENDER_RECEIVER.S)
  c.send(gsm.MESSAGE_TYPE.LOBBYSERVERLOGIN, [name, '1', '192.168.0.41', '255.255.255.0', '0'])
  c.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['23', ['2', '', '384']])
  c.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['9', ['2', '384']])
  return c

alice = lobby_join('127.0.0.2', 'alice')
alice.all()
bob = lobby_join('127.0.0.4', 'bob')
members = [m for m in lobby_msgs(bob) if m[0] == '53'][0][1][4]
check([m[0] for m in members] == ['alice', 'bob'] and '127.0.0.2' not in str(members), 'both are in the Ranked lobby; bob sees alice without her address')
alice.all()
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['12', ['2', "alice's Game", GAME, '1', '2', '0', ROOM_INFO, '', '', GS_VERSION, b'']])
room = [m for m in lobby_msgs(alice) if m[0] == '38'][0][1][1][0]
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['24', [room, '', '448', '0', GS_VERSION]])
new_group = [m for m in lobby_msgs(bob) if m[0] == '54']
check(len(new_group) == 1 and new_group[0][1][1] == "alice's Game", 'bob sees the new room')
alice.all()
bob.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['24', [room, '', '448', '0', GS_VERSION]])
got = lobby_msgs(bob)
check([m[0] for m in got] == ['53', '38', '50', '50'], 'joining: room data, the reply, then both members')
check('127.0.0.2' not in str(got), 'with the relay on, bob never sees alice\'s real address')
alice.all()
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['15', [room]])
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['33', [room, b'', str(relay_a), '']])
for who, conn in (('alice', alice), ('bob', bob)):
  started = [m for m in lobby_msgs(conn) if m[0] == '56']
  check(len(started) == 1 and started[0][1][0] == room, f'{who} gets GAME_STARTED')
started_bob = started[0][1]
check(started_bob[2:] == [str(relay_a), '127.0.0.1', '127.0.0.1'], 'GAME_STARTED gives bob the host\'s relay address')

# game traffic through the relay
game_b.sendto(b'hello host', ('127.0.0.1', relay_a))
data, src = game_a.recvfrom(2048)
check(data == b'hello host' and src == ('127.0.0.1', relay_b), 'the relay forwards bob -> alice from bob\'s relay port')
game_a.sendto(b'hello joiner', ('127.0.0.1', relay_b))
data, src = game_b.recvfrom(2048)
check(data == b'hello joiner' and src == ('127.0.0.1', relay_a), 'and alice -> bob from alice\'s relay port')

# rated match
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['17', [room, '1', '0']])
match_id = [m for m in lobby_msgs(bob) if m[0] == '62'][0][1][1]
alice.all()
def values(result):
  v = ['0'] * 22
  v[0], v[1], v[16], v[17] = result, '3', '131072', '600'
  return v
for conn in (alice, bob):
  conn.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['30', [match_id, '0', ['alice', '21', '22', '0', values('1')], ['bob', '21', '22', '0', values('0')]]])
  check(lobby_msgs(conn) == [['38', ['30', [match_id]]]], 'SUBMIT_MATCH is answered')
alice.send(gsm.MESSAGE_TYPE.LOBBY_MSG, ['45', [room]])
final = [m for m in lobby_msgs(bob) if m[0] == '71']
check(len(final) == 1 and final[0][1][:2] == [match_id, '38'], 'FINAL_MATCH_RESULTS reaches the room')
code, seq, result, row = ladder('alice')
check(row['RATING'] == '1516' and row['WINS'] == '1' and row['W_DUNGEON'] == '1' and row['TOT_TIME_PLAYED'] == '600', 'the rated result changes the ladder (#49)')

# --- IRC chat ---------------------------------------------------------------------------
class Chat:
  def __init__(self, src, nick):
    self.sock = socket.create_connection((HOST, PORT['irc']), timeout=2, source_address=(src, 0))
    self.buf = b''
    self.send(f'NICK :{nick}', f'USER {GAME} +i 0 :{nick}')

  def send(self, *lines):
    self.sock.sendall(b''.join(bytes(ircm.IRCMessage.from_str(l + '\r\n')) for l in lines))

  def read(self, wait=0.5):
    end, lines = time.monotonic() + wait, []
    while time.monotonic() < end:
      self.sock.settimeout(max(0.01, end - time.monotonic()))
      try:
        data = self.sock.recv(4096)
      except socket.timeout:
        break
      if not data:
        break
      self.buf += data
      while len(self.buf) >= 2 and len(self.buf) >= 2 + utils.read_u16_be(self.buf[:2]):
        size = utils.read_u16_be(self.buf[:2])
        lines += ircm.IRCMessage(self.buf[:2 + size]).payload.decode(errors='replace').split('\r\n')
        self.buf = self.buf[2 + size:]
    return [l for l in lines if l]

chan = f'#LobbyGrp1.{room}'
a_chat, b_chat = Chat('127.0.0.2', 'alice'), Chat('127.0.0.4', 'bob')
check(any(' 001 alice ' in l for l in a_chat.read()), 'IRC accepts the logged-in account name as the nick')
for c in (a_chat, b_chat):
  c.send(f'JOIN :{chan}')
  c.read()
b_chat.send(f'PRIVMSG {chan} :bob%16777215%9%0%0%Arial%1hello alice')
check(any(l.endswith(f'PRIVMSG {chan} :bob%16777215%9%0%0%Arial%1hello alice') for l in a_chat.read()), 'chat is relayed in the room channel')
mallory = Chat('127.0.0.9', 'carol')
check(any(' 432 carol ' in l for l in mallory.read()), 'IRC refuses a nick no account is logged in with from that address')

print(f'all {checks} checks passed')
