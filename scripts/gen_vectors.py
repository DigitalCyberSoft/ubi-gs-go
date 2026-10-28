#!/usr/bin/env python3
"""Dumps byte-exact test vectors from the Python ubi-gs (the reference implementation).

Usage: python3 scripts/gen_vectors.py <path to the ubi-gs checkout> > testdata/vectors.json

The Python repository needs its requirements (rsa, Flask, irc). Every vector is plain JSON with bytes
in hex; the Go tests in internal/... read testdata/vectors.json and compare their own output with it.
Nothing here is random except the RSA key, whose private part is dumped with it.
"""
import json, os, random, struct, sys

root = os.path.abspath(sys.argv[1])
# the reference prints as it works; keep that out of the JSON
vectors_out, sys.stdout = sys.stdout, sys.stderr
sys.path[:0] = [root, os.path.join(root, 'homm5')]
os.environ['UBIGS_DB'] = ':memory:'

import blowfish, gsxor, gsm, pkc, srp, utils, client, cdkm, ircm, h5_data  # noqa: E402
from data import List  # noqa: E402

rng = random.Random(5)
out = {}


def hx(b):
  return bytes(b).hex()


def jsonable(v):
  """A decoded data list as JSON: strings as {"s": hex}, binaries as {"b": hex}, lists as arrays."""
  if isinstance(v, list):
    return [jsonable(x) for x in v]
  if isinstance(v, (bytes, bytearray)):
    return {'b': hx(v)}
  # the reference reads bytes as Latin-1 characters
  return {'s': v.encode('latin-1').hex()}


def message(msg_type, data, sender=gsm.SENDER_RECEIVER.P, receiver=gsm.SENDER_RECEIVER.R):
  header = gsm.GSMessageHeader.from_params(gsm.PROPERTY.GS, 1, msg_type, sender, receiver)
  return bytes(gsm.GSMNotification(gsm.Message(None, header=header, dl=List(data))))


def req(msg_type, data, **kw):
  return gsm.Message(None, in_buf=message(msg_type, data, **kw))


# --- GS XOR -------------------------------------------------------------------
out['gsxor'] = []
for size in list(range(0, 40)) + [63, 64, 65, 100, 255, 256, 257, 1000, 4097]:
  data = bytes(rng.randrange(256) for _ in range(size))
  out['gsxor'].append({'plain': hx(data), 'enc': hx(gsxor.encrypt(data))})

# --- Blowfish -----------------------------------------------------------------
bf = blowfish.Blowfish(b'TESTKEY')
out['blowfish_block'] = [{'key': hx(b'TESTKEY'), 'l': l, 'r': r, 'el': bf.encrypt(l, r)[0], 'er': bf.encrypt(l, r)[1]}
  for l, r in [(1, 2), (0, 0), (0xFFFFFFFF, 0x12345678), (0xDEADBEEF, 0xCAFEBABE)]]
out['blowfish_cipher'] = []
for name, key in [('cdkey', b"SKJDHF$0maoijfn4i8$aJdnv1jaldifar93-AS_dfo;hjhC4jhflasnF3fnd"), ('irc', ircm.BLOWFISH_KEY), ('session', bytes(range(16)))]:
  cipher = blowfish.Cipher(key)
  for size in [0, 1, 7, 8, 9, 15, 16, 17, 100, 255]:
    data = bytes(rng.randrange(256) for _ in range(size))
    enc = cipher.encrypt(data)
    out['blowfish_cipher'].append({'name': name, 'key': hx(key), 'plain': hx(data), 'enc': hx(enc)})

# --- data lists ---------------------------------------------------------------
lists = [
  [], ['1'], ['a', b'', []], [['xd'], 'ddd'], ['38', ['21']], [b'\x01\x02', ['x', ['y', [b'z']]], ''],
  ['1281', '1', ['1', ['1', 'HEROES_657d2c2ebadc6a1d', '1', '0', ['1', ['alice', '1']], [[], [], []]]]],
]
out['dl'] = [{'value': jsonable(l), 'enc': hx(List(l).to_buf())} for l in lists]
# decoding quirks of the reference: a last single byte is ignored, decoding stops at ']'
out['dl_decode'] = []
for raw in [b's1\x00s2\x00x', b's1\x00]s2\x00', b'[]', b'[s1\x00]s2\x00', b'b\x00\x00\x00\x02hi', b's\x00\x00']:
  out['dl_decode'].append({'enc': hx(raw), 'value': jsonable(List.from_buf(bytearray(raw)).lst)})

# --- GS messages: requests as the game sends them and the reference's replies --------
ROOM_INFO = bytes.fromhex(
  "04080400000001d90200000208ffffffff0308ffffffff04240220000000000000000000000000000000000602000730"
  "61006c00690063006500270073002000470061006d00650008000902000a02000b02000c02000d08ffffffff0e080100"
  "00000f6602622f4d6170732f4d756c7469706c617965722f53342f53342e7864622378706f696e746572282f4164764d"
  "61704465736329132001080200000002100100000001000000140802000000150801000000161803080000000004080d"
  "00000017083c0001001802001920000000000000000000000000000000001a02001b5403080100000004080d00000001"
  "206175746f736176655f656e61626c65640214020800000000030430001c02001d087737aa291e08010000001f760272"
  "2f4d6170732f4d756c7469706c617965722f53342f6d61702d7461672e7864622378706f696e746572282f4164764d61"
  "704465736354616729200a676f616c352100250800000000260800000000270800000000280200000002000500"
)
replies = []
def reply(name, request, response):
  replies.append({'name': name, 'request': hx(request), 'response': hx(bytes(response))})

reply('stillalive', bytes([0, 0, 6, 1, 0x3A, 0x42]), gsm.StillAliveResponse(gsm.Message(None, in_buf=bytes([0, 0, 6, 1, 0x3A, 0x42]))))
m = message(gsm.MESSAGE_TYPE.LOGIN, ['alice', 'secret', 'HEROES_657d2c2ebadc6a1d'])
reply('login', m, gsm.LoginResponse(gsm.Message(None, in_buf=m)))
reply('login_fail', m, gsm.LoginFailResponse(gsm.Message(None, in_buf=m), 2))
m = message(gsm.MESSAGE_TYPE.JOINWAITMODULE, [])
reply('joinwaitmodule', m, gsm.JoinWaitModuleResponse(gsm.Message(None, in_buf=m), ('10.0.0.1', 7782)))
reply('proxy_joinwaitmodule', m, gsm.ProxyJoinWaitModuleResponse(gsm.Message(None, in_buf=m), ('10.0.0.1', 7784), 'averyveryverylongname'))
m = message(gsm.MESSAGE_TYPE.LOGINWAITMODULE, ['alice'])
reply('loginwaitmodule', m, gsm.LoginWaitModuleResponse(gsm.Message(None, in_buf=m)))
reply('proxy_loginwaitmodule', m, gsm.ProxyLoginWaitModuleResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.LOGIN, ['alice', 'HEROES_657d2c2ebadc6a1d'])
reply('proxy_login', m, gsm.ProxyLoginResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.PLAYERINFO, ['alice'])
reply('playerinfo', m, gsm.PlayerInfoResponse(gsm.Message(None, in_buf=m), 'alice'))
reply('playerinfo_long', m, gsm.PlayerInfoResponse(gsm.Message(None, in_buf=m), 'averyveryverylongname'))
m = message(gsm.MESSAGE_TYPE.LOGINFRIENDS, [b'\0\0\0\0', b'\0\0\0\0'])
reply('loginfriends', m, gsm.LoginFriendsResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.ADDFRIEND, ['bob', '', b'\0\0\0\0'])
reply('addfriend', m, gsm.FriendsResponse(gsm.Message(None, in_buf=m), ['bob']))
reply('addfriend_fail', m, gsm.FriendsFailResponse(gsm.Message(None, in_buf=m), 1))
m = message(gsm.MESSAGE_TYPE.FRIENDLIST, [])
reply('friendlist', m, gsm.FriendsResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.PROXY_HANDLER, ['1', ['ladderquery', '0', '0']])
reply('proxyhandler_1', m, gsm.ProxyHandlerResponse(gsm.Message(None, in_buf=m), ('10.0.0.1', 7783), '2'))
m = message(gsm.MESSAGE_TYPE.PROXY_HANDLER, ['2', ['2']])
reply('proxyhandler_2', m, gsm.ProxyHandlerResponse(gsm.Message(None, in_buf=m), ('10.0.0.1', 7783)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['3', ['1']])
reply('join_server', m, gsm.JoinLobbyServerResponse(gsm.Message(None, in_buf=m), ('10.0.0.1', 7785)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['21', ['HEROES_657d2c2ebadc6a1d']])
reply('lobby_login', m, gsm.LobbyMsgResponse(gsm.Message(None, in_buf=m)))
import router_wm  # noqa: E402
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['109', ['HEROES_657d2c2ebadc6a1d']])
reply('group_info', m, gsm.GroupInfoResponse(gsm.Message(None, in_buf=m), router_wm.LOBBIES))
m = message(gsm.MESSAGE_TYPE.LOBBYSERVERLOGIN, ['alice', '1', '192.168.0.41', '255.255.255.0', '0'], receiver=gsm.SENDER_RECEIVER.S)
reply('lobbyserverlogin', m, gsm.LobbyServerLoginResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['23', ['1', '', '384']], receiver=gsm.SENDER_RECEIVER.S)
reply('join_lobby', m, gsm.JoinLobbyResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['42', [b'data']], receiver=gsm.SENDER_RECEIVER.S)
reply('lobby_result', m, gsm.LobbyResultResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['15', ['1000']], receiver=gsm.SENDER_RECEIVER.S)
reply('lobby_group', m, gsm.LobbyGroupResponse(gsm.Message(None, in_buf=m)))
m = message(gsm.MESSAGE_TYPE.LOBBY_MSG, ['12', ['1', "alice's Game", 'HEROES_657d2c2ebadc6a1d', '7', '2', '0', ROOM_INFO, '', '', 'HEROES_c83663d1c69a2024', b'']], receiver=gsm.SENDER_RECEIVER.S)
rooms = []
reply('create_room', m, gsm.CreateRoomResponse(gsm.Message(None, in_buf=m), rooms, 1000, 'alice'))
out['replies'] = replies

# notifications
upd = gsm.update_friend('bob', True)
out['update_friend_online'] = hx(bytes(gsm.GSMNotification(upd)))
out['update_friend_offline'] = hx(bytes(gsm.GSMNotification(gsm.update_friend('bob', False))))

# room data as the lobby sends it (the room info rebuilt by the reference's serializer)
import lobby  # noqa: E402
room = rooms[0]
room.gs_room.ip_addr = '10.0.0.2'
out['room_list'] = jsonable(lobby.room_list(room))
out['room_info_reserialized'] = hx(room.gs_room.group_info)
ser = h5_data.H5_Serializer()
info = ser.deserialize_roominfo(ROOM_INFO)
out['room_info_input'] = hx(ROOM_INFO)
out['room_info_output'] = hx(ser.serialize_roominfo(info))
entry = h5_data.H5_PlayerInfo()
entry.username = 'alice'
entry.ext_ip.family = 2
entry.ext_ip.port = 8888
entry.ext_ip.ip = '10.0.0.2'
entry.local_port = 8888
entry.local_ip.ip = '192.168.0.41'
entry.int38 = 1500
out['player_info'] = hx(ser.serialize_playerinfo(entry))
info.player_infos.append(entry)
out['room_info_with_player'] = hx(ser.serialize_roominfo(info))

# --- ladder and profile module data ---------------------------------------------
import accounts, proxy_wm, ladder  # noqa: E402
accounts.configure(':memory:')
alice = accounts.login('alice', 'pw')
accounts.bind_session('alice', '10.0.0.3', alice)
accounts.set_ladder_stats(alice, ladder.ladder_key('HEROES_657d2c2ebadc6a1d', '1'), {'RATING': 1612, 'WINS': 3})
c = client.TcpClient((None, ('10.0.0.3', 50000)))
module = []
for code, seq, payload in [
  ('1281', '7', ['1', ['1', 'HEROES_657d2c2ebadc6a1d', '1', '0', ['1', ['alice', '1']], [[], [], []]]]),
  ('1281', '8', ['1', ['1', 'HEROES_657d2c2ebadc6a1d', '1', '0', ['1', ['nobody', '1']], [[], [], []]]]),
  ('1025', '1', ['HEROES_657d2c2ebadc6a1d', '0', 'alice', '0', 'PUBLIC']),
  ('1026', '2', ['HEROES_657d2c2ebadc6a1d', '0', 'alice', '0', 'PUBLIC', bytes(range(256)) * 3, '768']),
  ('1025', '3', ['HEROES_657d2c2ebadc6a1d', '0', 'alice', '0', 'PUBLIC']),
]:
  m = message(gsm.MESSAGE_TYPE.PROXY_HANDLER, [code, seq, payload])
  module.append({'request': hx(m), 'response': hx(bytes(proxy_wm.handle_req(c, gsm.Message(None, in_buf=m))))})
out['module'] = module

# --- NAT and SRP ----------------------------------------------------------------
nat_req = message(gsm.MESSAGE_TYPE.NAT, ['1', ['1', '', 'HEROES_657d2c2ebadc6a1d', 'HEROES_c83663d1c69a2024']],
  sender=gsm.SENDER_RECEIVER.UNK, receiver=gsm.SENDER_RECEIVER.S)
out['nat_request'] = hx(nat_req)
nr = gsm.Message(None, in_buf=nat_req)
out['nat_port_id'] = hx(bytes(gsm.NatResponse(nr, gsm.NAT_MSG.PORT_ID, 0xDEADBEEF, 7781)))
out['nat_address'] = hx(bytes(gsm.NatResponse(nr, gsm.NAT_MSG.ADDRESS, utils.ipv4_to_u32_be('192.168.0.41'), 8888)))
syn = struct.pack('<HHHHHH', 0, 1, 8, 2 | 0x3040, 0, 0) + struct.pack('<HHHH', 10, 1, 0x1AB7, 0x218)
clt = client.NatClient(('127.0.0.1', 1024), None, None)
out['srp_syn'] = hx(syn)
out['srp_syn_ack'] = hx(bytes(srp.SRPResponse(srp.SRPRequest(syn), clt)))
seg = struct.pack('<HHHHHH', 0, 1, len(nat_req), 0x3040, 1, 0) + nat_req
out['srp_msg'] = hx(seg)
sreq = srp.SRPRequest(seg)
out['srp_msg_reply'] = hx(bytes(srp.SRPResponse(sreq, clt, gsm.NatResponse(sreq.segment.msg, gsm.NAT_MSG.PORT_ID, 5, 7781))))
out['srp_server_initiated'] = hx(bytes(srp.SRPResponse(None, clt, gsm.NatResponse(sreq.segment.msg, gsm.NAT_MSG.ADDRESS, 0x7F000001, 8888))))
out['srp_checksum'] = []
for size in [1, 2, 3, 12, 13, 31, 64, 65]:
  data = bytes(rng.randrange(256) for _ in range(size))
  out['srp_checksum'].append({'data': hx(data), 'sum': int.from_bytes(srp.SRPResponse._SRPResponse__make_checksum(data), 'little')})

# --- CD key -------------------------------------------------------------------
def cdkey_request(msg_id, req_type, data):
  lst = [msg_id, str(req_type)] if data is None else [msg_id, str(req_type), '1', data]
  dl = bytearray(bytes(List(lst)))
  dl.pop(0); dl.pop()
  enc = cdkm.BLOWFISH.encrypt(bytes(dl))
  return bytes([1]) + utils.write_u32_be(len(enc)) + enc

import cdkey  # noqa: E402
out['cdkey'] = []
for msg_id, t, data in [('1', 1, []), ('2', 2, [b'K' * 20]), ('3', 3, [b'A' * 16]), ('4', 4, [b'V' * 16]), ('5', 7, None), ('6', 6, [bytes(20)])]:
  rq = cdkey_request(msg_id, t, data)
  rs = cdkey.handle_packet(rq)
  out['cdkey'].append({'request': hx(rq), 'response': hx(rs) if rs is not None else None})

# --- IRC frames -----------------------------------------------------------------
out['irc'] = []
for line in [':localhost 001 alice :Welcome to GS IRC v1.0.0.\r\n', 'PRIVMSG #LobbyGrp1.1000 :bob%16777215%9%0%0%Arial%1hello\r\n', '\r\n']:
  out['irc'].append({'line': hx(line.encode()), 'frame': hx(bytes(ircm.IRCMessage.from_str(line)))})
out['chat'] = []
import gsirc  # noqa: E402
for nick, payload in [('bob', ':bob%16777215%9%0%0%Arial%1hello'), ('bob', ':alice%16777215%9%0%0%Arial%1I give up'),
                      ('bob', ':bob%16777215%9%0%0%Arial%2alice has left the game'), ('bob', ':bob%1%9%0%0%Arial%2bob has joined'),
                      ('bob', 'plain text'), ('bob', 'bob%red%9%0%0%Arial%1hi'), ('bob', 'bob%1%9%0%0%<b>%1hi'),
                      ('bob', 'x%1%9%0%0%Arial%1a\x01b\x7fc%d')]:
  out['chat'].append({'nick': nick, 'payload': payload, 'result': gsirc.sanitize_chat(nick, payload)})

# --- RSA ------------------------------------------------------------------------
pub, priv = pkc.keygen()
msg = bytes(range(16))
out['rsa'] = {'n': format(priv.n, 'x'), 'e': priv.e, 'd': format(priv.d, 'x'), 'plain': hx(msg),
  'cipher': hx(pkc.encrypt(msg, pub)), 'pubkey': hx(bytes(pkc.RsaPublicKey.from_pubkey(pub)))}

# --- accounts names -------------------------------------------------------------
out['family'] = [{'name': n, 'k': k, 'family': accounts.family_name(n, k)} for n, k in [('alice', 1), ('abcdefghijk', 1), ('abcdefghijk', 10), ('ab', 3)]]

json.dump(out, vectors_out, indent=1, sort_keys=True)
vectors_out.write('\n')
