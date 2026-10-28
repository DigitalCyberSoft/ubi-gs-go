//go:build !windows

package server

import "syscall"

// reuseAddr lets a restart bind while old connections close; on Linux and macOS this never allows two
// listeners on one port.
func reuseAddr(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
