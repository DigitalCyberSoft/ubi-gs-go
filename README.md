# ubi-gs-go

A Go rewrite of [ubi-gs](https://github.com/michal-kapala/ubi-gs), the community emulator of Ubisoft's Game Service (ubi.com) servers, for **Heroes of Might and Magic V** online play. It follows the [DigitalCyberSoft fork](https://github.com/DigitalCyberSoft/ubi-gs), which added the lobby, match start, rated matches, accounts, friends, ladder, profiles and the security fixes.

One process, one static binary: `ubi-gs` runs every service the game talks to.

| Service | Port | Protocol |
|---|---|---|
| gsconnect (serves `servers.ini`) | 80 | TCP (HTTP) |
| router | 7777 | TCP |
| IRC chat | 7779 | TCP |
| CD key | 7780 | UDP |
| NAT | 7781 | UDP |
| router wait module | 7782 | TCP |
| proxy | 7783 | TCP |
| proxy wait module | 7784 | TCP |
| lobby | 7785 | TCP |
| game traffic relay (on by default) | 9000-9999 | UDP |

The services share their state in memory (accounts, lobby rooms and members, NAT clients, IRC channels), so `UBIGS_DB=:memory:` works, and there is nothing to start one by one.

## Getting the binary

Download the binary for your system from the releases, or build it. Building needs Go 1.25 or newer and no C compiler:

```
git clone <this repository> ubi-gs-go
cd ubi-gs-go
make                 # ./ubi-gs for this system
make all             # dist/ubi-gs-<os>-<arch> for linux/amd64, linux/arm64, windows/amd64, darwin/arm64, darwin/amd64
```

Without make: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ubi-gs ./cmd/ubi-gs`, with `GOOS`/`GOARCH` set to cross-compile. The binaries are about 10 MB.

## Running it

```
./ubi-gs
```

That's all: every service starts, listening on all interfaces. Ctrl+C or SIGTERM stops them cleanly (the database is closed properly). Each log line has a timestamp; `--quiet` logs only warnings and errors, `--verbose` logs every message (passwords and CD-key data are left out).

Accounts, friends, ratings and profiles are kept in `ubigs.db` in the current directory. A database from the Python version keeps working: the schema is the same, and logins, passwords included, carry over.

### Settings

Every setting is a command-line option or an environment variable; the option wins. `ubi-gs --help` lists them.

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--bind` | `UBIGS_BIND` | `0.0.0.0` | Address the services listen on. |
| `--host` | `UBIGS_HOST` | (none) | Address or host name given to players in `servers.ini` and redirects. Without it, each player is given the address it reached the server on. Set it behind NAT, port forwarding or a reverse proxy. |
| `--db` | `UBIGS_DB` | `ubigs.db` | Accounts database file, or `:memory:` to keep everything in memory only (lost on exit). |
| `--socket-timeout` | `UBIGS_SOCKET_TIMEOUT` | `180` | Seconds a connection may stay silent (the game sends a keepalive every 30 s and gives up after 105 s). |
| `--max-connections` | `UBIGS_MAX_CONNECTIONS` | `512` | Connections per service. |
| `--max-per-ip` | `UBIGS_MAX_PER_IP` | `16` | Connections per service from one address (players behind one NAT share it); also NAT entries and relay ports per address. |
| `--max-nat-clients` | `UBIGS_MAX_NAT_CLIENTS` | `4096` | NAT table size. |
| `--gsconnect-port` | `GSCONNECT_PORT` | `80` | gsconnect's port. The game always asks port 80; change it only behind a reverse proxy. |
| `--gsconnect-bind` | `GSCONNECT_HOST` | `--bind` | Address gsconnect listens on. |
| `--no-gsconnect` | `UBIGS_GSCONNECT=off` | | Don't serve gsconnect (for example, it runs elsewhere). |
| `--port-offset` | `UBIGS_PORT_OFFSET` | `0` | Moves the ports 7777-7785; `servers.ini` follows, so the game still finds them. For a second server on one machine. |
| `--relay` | `UBIGS_RELAY` | on | Relay the players' game traffic (see [Privacy](#privacy-player-addresses-and-the-relay)). `--relay=false` or `UBIGS_RELAY=off` turns it off. |
| `--relay-ports` | `UBIGS_RELAY_PORTS` | `9000-9999` | UDP ports for relayed players, one per player. |
| `--relay-max-packets` | `UBIGS_RELAY_MAX_PACKETS` | `400` | Datagrams per second the relay forwards to one player. |
| `--relay-max-kbps` | `UBIGS_RELAY_MAX_KBPS` | `256` | KiB per second the relay forwards to one player. |
| `--server-id` | `UBIGS_SERVER_ID` | (stored) | The server's identity, 16-64 hex digits (see [HommaRe logins](#hommare-logins-and-the-server-id)). |
| `--max-new-accounts-per-ip-hour` | `UBIGS_MAX_NEW_ACCOUNTS_PER_IP_HOUR` | `5` | Accounts one address may create per hour (0: no limit). |
| `--max-accounts` | `UBIGS_MAX_ACCOUNTS` | `100000` | Accounts stored in total (0: no limit). |
| `--max-logins-per-ip-minute` | `UBIGS_MAX_LOGINS_PER_IP_MINUTE` | `20` | Login attempts per address per minute (0: no limit). |
| `--hash-workers` | `UBIGS_HASH_WORKERS` | CPU count | Password hashes computed at once. |
| `--prune-days` | `UBIGS_PRUNE_DAYS` | `0` | Delete accounts that never reached the lobby after this many days (0: never). |
| `--no-firewall-check` | `UBIGS_FIREWALL_CHECK=off` | | Skip the read-only firewall check at start. |
| `--quiet`, `--verbose` | `UBIGS_QUIET`, `UBIGS_VERBOSE` | | Log level. |

## Pointing the game at the server

The game asks `http://gsconnect.ubisoft.com/gsinit.php?dp=<game id>` for the server list, with its bundled libcurl over plain HTTP. Make `gsconnect.ubisoft.com` reach the server; no game files change.

- **Windows:** open Notepad as administrator, open `C:\Windows\System32\drivers\etc\hosts` (choose "All files"), add a line with the server's address, save, then run `ipconfig /flushdns`:
  ```
  203.0.113.10 gsconnect.ubisoft.com
  ```
  Remove the line to go back.
- **Linux (Wine, Proton, Lutris, Steam):** add the same line to `/etc/hosts` as root, or, without root, start the game with an HTTP proxy pointing at gsconnect. The game's libcurl honours `http_proxy`, and gsconnect answers proxy-style requests:
  ```
  http_proxy=http://203.0.113.10:80 wine H5_Game.exe
  ```
  For Steam, use the launch options `http_proxy=http://203.0.113.10:80 %command%`.
- **HommaRe** (the native port): its Multi Player menu has an "ubi-gs" entry that asks for the server's address, so no hosts file or proxy is needed.

The game ids of Heroes V 1.60, Hammers of Fate 2.1 and Tribes of the East 3.1 are all accepted; only 1.60 has been played against the server.

**Logging in:** Multi Player, ubi.com, any CD key, then any name and password. The first login creates the account.
- The same name and password later gets the same account back, with its friends, rating and profile.
- If the name belongs to someone else (another password), you get the next free name: `name-1`, `name-2`, ... Log in again with the same name and password to get that same account. (Known limitation: the game keeps the name you typed, so your own lists show you as `name`, while others see `name-1`.)
- Names are case-insensitive, at most 11 bytes, no spaces or control characters.
- Logging in again closes your older connection (after a crash, for example).

**Playing:** in a room, every player marks themselves ready with the small arrow next to their own state icon; then the host's Start Game turns on. Rated games are played in the Ranked channel; their results update the ladder (Elo, starting at 1500) and the per-race statistics the Profile screen reads. The game reads its own rating for the player list when it logs in, so a new rating shows there after the next login.

## Privacy: player addresses and the relay

Heroes V matches are peer-to-peer: the games send their game traffic (UDP, port 8888 by default) to each other.

- **Addresses only within a room.** The lobby never shows a player's address to the rest of the lobby: member lists, room lists and IRC carry `0.0.0.0` instead. A player's address goes only to the members of the room it joined, where the game needs it for the peer connection.
- **The relay (on by default).** With the relay on, no player learns another's address at all, not even in a room. Each player gets a relay port on the server (`--relay-ports`), and every address a game is told is a relay address: in the NAT service's reply (which the game puts in its room data as its own address), the room data, member data and the match start. The server forwards the game traffic between the players of a room. Only players the NAT service has verified, and only players in the same room or match, are forwarded between, at a capped rate, so the relay can't be used to send traffic to arbitrary hosts. Relay ports are freed when a player leaves the server or after 5 minutes unused.
  - **No port forwarding needed.** Players don't need to forward port 8888 to host games: all their traffic is outgoing.
  - **The cost:** the server carries every match's traffic. A two-player match measured 300-400 bytes per second in total (about 1.5 MB an hour), and the relay added 0.1 ms per datagram (median; 1.9 ms at the 95th percentile) on the test machine.
  - **The trust:** players must trust the operator, who could see or disrupt their game traffic (which isn't encrypted in any case).
- With `--relay=false`, matches connect directly between the players as with the original servers: room members see each other's addresses, and the host may need to forward its game port.

## HommaRe logins and the server ID

HommaRe doesn't send a player's real password. It registers a token derived from the password, the account name and the server's identity, then answers a single-use challenge for each login. The original game keeps sending its password, which works as always.

- `servers.ini` carries `ServerID=<hex>`, a random 128-bit value created once and kept in the database, and `LoginNonce=<hex>`, a fresh single-use value for the address that asked, valid for 5 minutes.
- **Keep your database, or set `UBIGS_SERVER_ID`, or HommaRe players' logins change.** HommaRe derives its token from the server ID; a new ID (a new database, or `:memory:`) gives every HommaRe player a different token, so they would get new `name-1` accounts. When moving a server, copy `ubigs.db`, or set `--server-id` to the old ID (the log prints it at start).
- Token accounts (HommaRe) and plain accounts (the original game) never mix: a name that belongs to the other kind is a collision, and the player gets `name-1`.

## Running it publicly

The server is public by default: it listens on all interfaces, and players reach it over the internet.

- **Firewall.** Open the ports in the table at the top: TCP 80, 7777, 7779, 7782-7785 and UDP 7780, 7781, plus UDP 9000-9999 for the relay. After starting, the server checks the host firewall (reading only, never changing anything) and prints what to run if a port looks closed: `netsh` rules on Windows; `ufw`, `firewalld` or `iptables`/`nftables` commands on Linux. A router in front of the server must forward the same ports.
- **Port 80 without root.** Don't run the server as root. Give the binary the capability (`sudo setcap cap_net_bind_service=+ep ./ubi-gs`), use systemd's `AmbientCapabilities=CAP_NET_BIND_SERVICE`, or run gsconnect on a high port behind a reverse proxy on port 80 (`--gsconnect-port 8080`, with `--host` set to the public address).
- **Limits.** Each service caps connections in total and per address, and closes silent ones. The NAT table and the relay are capped too. Logins are rate-limited per address, with a growing wait after password misses; new accounts are limited per address and in total; password hashing (scrypt, N=2^14, r=8, p=1, about 65 ms per hash, the same parameters as the Python version so its databases keep working) runs on at most one worker per CPU. Refusals use the game's own login error codes.
- **Logs** hold player names, addresses and chat, but never passwords or CD-key data. Keep them private.

**What players must know:**
- **Names are unauthenticated beyond the first-login password.** Whoever logs in first with a name owns it.
- **Use a throwaway password.** The 2006 protocol has no real encryption: keyless XOR, Blowfish keys shared by every copy of the game, RSA-512 with e=3, no TLS. Anyone on the network path can read the password. (HommaRe sends a derived token instead.)
- **Other players may see your address.** Without the relay, the members of your room see it (peer-to-peer matches need it). With the relay, they see only the server's.
- **Only join servers you trust.** The original Windows client trusts the server: its network code copies strings into fixed buffers, so a hostile server could crash or corrupt it.

## Troubleshooting ports

If a port can't be opened, the server prints one line naming the service, the protocol and port, the reason and the fix, and exits with code 2. Nothing runs half-started.

- **"another program is already using it"** (Linux EADDRINUSE, Windows 10048): another program, or another copy of the server, holds the port; the message names it when it can. Find it with `sudo ss -ltnp 'sport = :7777'` (TCP) or `sudo ss -lunp 'sport = :7780'` (UDP) on Linux, `sudo lsof -nP -i TCP:7777` on macOS, `netstat -ano -p TCP | findstr :7777` then `tasklist /FI "PID eq <pid>"` on Windows.
- **Linux, "ports below 1024 need root"** (EACCES, gsconnect on port 80): see "Port 80 without root" above.
- **Windows, "Windows refused access"** (10013):
  - Port 80 is often held by HTTP.sys (the "System" process, PID 4: IIS, the World Wide Web Publishing Service). Check with `netsh http show servicestate`; stop the service (`net stop w3svc` as administrator) or run gsconnect elsewhere.
  - Any port can fall in a range reserved by Hyper-V, WSL or Docker: `netsh int ipv4 show excludedportrange protocol=tcp` (and `udp`). `net stop winnat` then `net start winnat` as administrator usually frees them.
- **"the address ... is not on this machine":** `--bind` isn't one of this machine's addresses; use `0.0.0.0`.
- **The server runs but players can't connect:** read the firewall warning printed at start, and check the router's port forwarding.

## Development

```
make test          # unit tests
make race          # with the race detector
make fuzz          # each fuzz target for 15 s (FUZZTIME=1m for longer)
make conformance UBIGS_REF=../ubi-gs UBIGS_PYTHON=../ubi-gs/.venv/bin/python
```

- The unit tests compare every encoder and decoder with vectors dumped from the Python version (`scripts/gen_vectors.py`, output in `testdata/vectors.json`).
- The conformance test starts the binary and drives it with a client built from the Python version's own protocol modules (`tests/conformance/client.py`): login with the RSA key exchange, two players, a room, the match start, a rated result, friends, the ladder, the relay and IRC chat.

Layout: `cmd/ubi-gs` (the command), `internal/server` (wiring), and one package per part: `dl` (data lists), `crypto` (GS XOR, Blowfish, RSA), `gsm` (messages), `h5` (room and player info), `router`, `proxy`, `lobby`, `ratings`, `irc`, `cdkey`, `srp` and `nat`, `relay`, `gsconnect`, `accounts`, `guard` and `challenge` (login limits and HommaRe logins), `limits`, `netsrv`, `ports` and `firewall`.

## Licence and credits

MIT, see [LICENSE](LICENSE). Based on ubi-gs by michal-kapala and the DigitalCyberSoft fork.

This project is not maintained by or affiliated with Ubisoft or Nival. The services were developed by reverse engineering, on the basis of Ubisoft's end-of-life [announcement](https://www.ubisoft.com/en-us/help/purchases-and-rewards/article/decommissioning-of-online-services-for-older-legacy-ubisoft-games-a-m/000064576) for the game's online services. All rights belong to their respective owners.
