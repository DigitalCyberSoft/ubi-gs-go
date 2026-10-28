// Package env holds what the Heroes V services share: their ports, the advertised address and the
// accounts store.
package env

import (
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

// Service ports, as in the game's servers.ini.
const (
	PortGSConnect = 80
	PortRouter    = 7777
	PortIRC       = 7779
	PortCDKey     = 7780
	PortNAT       = 7781
	PortRouterWM  = 7782
	PortProxy     = 7783
	PortProxyWM   = 7784
	PortLobby     = 7785
)

// Ports are the services' ports; tests move them.
type Ports struct {
	Router, IRC, CDKey, NAT, RouterWM, Proxy, ProxyWM, Lobby int
}

// DefaultPorts are the ports the game's servers.ini names.
func DefaultPorts() Ports {
	return Ports{PortRouter, PortIRC, PortCDKey, PortNAT, PortRouterWM, PortProxy, PortProxyWM, PortLobby}
}

// Env is shared by the services.
type Env struct {
	Accounts *accounts.Store
	// Host is the address given to the game in redirects (UBIGS_HOST); empty means the address the game
	// reached the service on.
	Host  string
	Ports Ports
}

// Advertise returns the address to send a game connected on c for another service.
func (e *Env) Advertise(c *netsrv.Conn) string {
	if e.Host != "" {
		return e.Host
	}
	return c.LocalIP()
}
