//go:build !linux

package kepr

import "net"

// checkPeer: SO_PEERCRED is Linux-only; elsewhere the socket's directory
// permissions are the guard.
func checkPeer(net.Conn) error { return nil }
