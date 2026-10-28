//go:build windows

package server

import "syscall"

// reuseAddr does nothing on Windows, where SO_REUSEADDR would let a second server share the port.
func reuseAddr(network, address string, c syscall.RawConn) error { return nil }
