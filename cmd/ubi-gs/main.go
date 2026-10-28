// Command ubi-gs runs every Ubisoft Game Service for Heroes of Might and Magic V in one process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/guard"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/limits"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/ports"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/relay"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/server"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `ubi-gs %s: Ubisoft Game Service emulator for Heroes of Might and Magic V.

One process runs everything: gsconnect (HTTP), router, router and proxy wait modules,
proxy, lobby, IRC chat, CD key and NAT, and the game traffic relay.

Usage: ubi-gs [options]

Every option can also be set with the environment variable in brackets; an option on
the command line wins.

`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	cfg     server.Config
	quiet   bool
	verbose bool
	version bool
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) (int, error) {
	v := env(name, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number", name, v)
	}
	return n, nil
}

func envFloat(name string, def float64) (float64, error) {
	v := env(name, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number", name, v)
	}
	return n, nil
}

func envBool(name string, def bool) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(env(name, "")))
	switch v {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s=%q is not on or off", name, v)
}

// parseRange reads "9000-9999".
func parseRange(s string) (int, int, error) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(s), "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return 0, 0, fmt.Errorf("relay ports %q: expected a range like 9000-9999", s)
	}
	return a, b, nil
}

func parse(args []string, stderr io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("ubi-gs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, usage, version)
		fs.PrintDefaults()
	}
	var errs []error
	ei := func(name string, def int) int {
		n, err := envInt(name, def)
		if err != nil {
			errs = append(errs, err)
		}
		return n
	}
	ef := func(name string, def float64) float64 {
		n, err := envFloat(name, def)
		if err != nil {
			errs = append(errs, err)
		}
		return n
	}
	eb := func(name string, def bool) bool {
		n, err := envBool(name, def)
		if err != nil {
			errs = append(errs, err)
		}
		return n
	}
	c := &o.cfg
	gd := guard.Defaults()
	fs.StringVar(&c.Bind, "bind", env("UBIGS_BIND", "0.0.0.0"), "address the services listen on [UBIGS_BIND]")
	fs.StringVar(&c.Host, "host", env("UBIGS_HOST", ""), "address or host name given to players; default: the address each player reached [UBIGS_HOST]")
	fs.StringVar(&c.DB, "db", env("UBIGS_DB", "ubigs.db"), "accounts database file, or :memory: [UBIGS_DB]")
	timeout := fs.Float64("socket-timeout", ef("UBIGS_SOCKET_TIMEOUT", limits.DefaultSocketTimeout), "seconds a connection may stay silent [UBIGS_SOCKET_TIMEOUT]")
	fs.IntVar(&c.MaxConns, "max-connections", ei("UBIGS_MAX_CONNECTIONS", limits.DefaultMaxConnections), "connections per service [UBIGS_MAX_CONNECTIONS]")
	fs.IntVar(&c.MaxPerIP, "max-per-ip", ei("UBIGS_MAX_PER_IP", limits.DefaultMaxPerIP), "connections per service from one address [UBIGS_MAX_PER_IP]")
	fs.IntVar(&c.MaxNATClients, "max-nat-clients", ei("UBIGS_MAX_NAT_CLIENTS", limits.DefaultMaxNATClients), "NAT table size [UBIGS_MAX_NAT_CLIENTS]")
	fs.IntVar(&c.PortOffset, "port-offset", ei("UBIGS_PORT_OFFSET", 0), "move every service port (7777-7785) by this much; servers.ini follows [UBIGS_PORT_OFFSET]")
	noGS := fs.Bool("no-gsconnect", !eb("UBIGS_GSCONNECT", true), "don't serve gsconnect (e.g. it runs behind a reverse proxy elsewhere) [UBIGS_GSCONNECT=off]")
	fs.StringVar(&c.GSConnectBind, "gsconnect-bind", env("GSCONNECT_HOST", ""), "address gsconnect listens on; default: --bind [GSCONNECT_HOST]")
	fs.IntVar(&c.GSConnectPort, "gsconnect-port", ei("GSCONNECT_PORT", 80), "gsconnect's port; the game asks port 80 [GSCONNECT_PORT]")
	fs.BoolVar(&c.Relay, "relay", eb("UBIGS_RELAY", true), "relay the players' game traffic so they never see each other's address [UBIGS_RELAY]")
	relayPorts := fs.String("relay-ports", env("UBIGS_RELAY_PORTS", fmt.Sprintf("%d-%d", relay.DefaultPortMin, relay.DefaultPortMax)), "UDP ports for relayed players [UBIGS_RELAY_PORTS]")
	fs.Float64Var(&c.RelayPacketsPerS, "relay-max-packets", ef("UBIGS_RELAY_MAX_PACKETS", relay.DefaultPacketsPerSecond), "datagrams per second the relay forwards to one player [UBIGS_RELAY_MAX_PACKETS]")
	relayKBps := fs.Float64("relay-max-kbps", ef("UBIGS_RELAY_MAX_KBPS", relay.DefaultBytesPerSecond/1024), "KiB per second the relay forwards to one player [UBIGS_RELAY_MAX_KBPS]")
	fs.IntVar(&c.Guard.NewAccountsPerIPHour, "max-new-accounts-per-ip-hour", ei("UBIGS_MAX_NEW_ACCOUNTS_PER_IP_HOUR", gd.NewAccountsPerIPHour), "accounts one address may create per hour; 0: no limit [UBIGS_MAX_NEW_ACCOUNTS_PER_IP_HOUR]")
	maxAccounts := fs.Int("max-accounts", ei("UBIGS_MAX_ACCOUNTS", int(gd.MaxAccounts)), "accounts stored in total; 0: no limit [UBIGS_MAX_ACCOUNTS]")
	fs.IntVar(&c.Guard.LoginsPerIPMinute, "max-logins-per-ip-minute", ei("UBIGS_MAX_LOGINS_PER_IP_MINUTE", gd.LoginsPerIPMinute), "login attempts per address per minute; 0: no limit [UBIGS_MAX_LOGINS_PER_IP_MINUTE]")
	fs.IntVar(&c.Guard.HashWorkers, "hash-workers", ei("UBIGS_HASH_WORKERS", 0), "password hashes at once; 0: the CPU count [UBIGS_HASH_WORKERS]")
	fs.IntVar(&c.PruneDays, "prune-days", ei("UBIGS_PRUNE_DAYS", 0), "delete accounts that never reached the lobby after this many days; 0: never [UBIGS_PRUNE_DAYS]")
	noFW := fs.Bool("no-firewall-check", !eb("UBIGS_FIREWALL_CHECK", true), "skip the read-only firewall check at start [UBIGS_FIREWALL_CHECK=off]")
	fs.BoolVar(&o.quiet, "quiet", eb("UBIGS_QUIET", false), "log warnings and errors only [UBIGS_QUIET]")
	fs.BoolVar(&o.verbose, "verbose", eb("UBIGS_VERBOSE", false), "log every message (passwords and key data left out) [UBIGS_VERBOSE]")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (see --help)", fs.Arg(0))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if *timeout <= 0 {
		return nil, errors.New("--socket-timeout must be above 0")
	}
	c.SocketTimeout = time.Duration(*timeout * float64(time.Second))
	c.GSConnect = !*noGS
	if c.GSConnectBind == "" {
		c.GSConnectBind = c.Bind
	}
	c.FirewallCheck = !*noFW
	c.Guard.MaxAccounts = int64(*maxAccounts)
	c.Guard.MaxBackoff = gd.MaxBackoff
	c.RelayBytesPerS = *relayKBps * 1024
	var err error
	if c.RelayMin, c.RelayMax, err = parseRange(*relayPorts); err != nil {
		return nil, err
	}
	if c.MaxConns < 1 || c.MaxPerIP < 1 || c.MaxNATClients < 1 {
		return nil, errors.New("connection limits must be at least 1")
	}
	if o.quiet && o.verbose {
		return nil, errors.New("--quiet and --verbose don't go together")
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "ubi-gs:", err)
		return 2
	}
	if o.version {
		fmt.Fprintln(stdout, "ubi-gs", version)
		return 0
	}
	level := logx.Normal
	if o.quiet {
		level = logx.Quiet
	} else if o.verbose {
		level = logx.Verbose
	}
	log := logx.New(stdout, level)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Infof("ubi-gs %s starting", version)
	srv, err := server.Start(ctx, o.cfg, log)
	if err != nil {
		var be *server.BindError
		if errors.As(err, &be) {
			fmt.Fprintln(stderr, be.Message)
			return ports.ExitBind
		}
		fmt.Fprintln(stderr, "ubi-gs:", err)
		return 1
	}
	log.Infof("all services started; Ctrl+C stops them")
	if o.cfg.FirewallCheck {
		go func() {
			if text := srv.FirewallWarning(); text != "" {
				fmt.Fprintln(stderr, text)
			}
		}()
	}
	<-ctx.Done()
	stop()
	log.Infof("stopping")
	srv.Shutdown()
	log.Infof("stopped")
	return 0
}
