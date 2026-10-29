//go:build linux

package kepr

import (
	"net"
	"os"
	"syscall"
)

// checkPeer refuses a socket whose server is not the daemon we expect:
// root's in system mode, otherwise this user's (SO_PEERCRED).
func checkPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return &Error{"cannot check the credential service"}
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || serr != nil {
		return &Error{"cannot check the credential service"}
	}
	want := uint32(os.Geteuid())
	if os.Getenv("KEPR_SYSTEM_MODE") != "" {
		want = 0
	}
	if cred.Uid != want {
		return &Error{"the socket is not served by the expected credential daemon"}
	}
	return nil
}
