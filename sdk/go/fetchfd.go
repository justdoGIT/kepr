package kepr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// FetchFDCmd is the request for pull-on-demand fd delivery (plan T3.06).
const FetchFDCmd = "fetch_fd"

// FetchFD fetches name as a sealed in-memory file (plan T3.06). The daemon
// applies the same checks as Get; the descriptor is close-on-exec, so
// children never inherit it. The caller owns the file and must Close it;
// n is the value's length. Needs a daemon with fd delivery.
func (c *Client) FetchFD(name string) (f *os.File, n int, err error) {
	nm, err := upper(name)
	if err != nil {
		return nil, 0, err
	}
	payload, _ := json.Marshal(map[string]any{"cmd": FetchFDCmd, "name": nm})
	addr := &net.UnixAddr{Name: c.Path, Net: "unix"}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, 0, &Error{fmt.Sprintf("cannot reach the credential service at %s (%v)", c.Path, err)}
	}
	defer conn.Close()
	if err := checkPeer(conn); err != nil {
		return nil, 0, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := conn.Write(frame); err != nil {
		return nil, 0, &Error{err.Error()}
	}
	// Exact reads only: the descriptor rides on the byte after the frame,
	// and a plain read of that byte would drop it.
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, 0, &Error{"connection closed by the credential service"}
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > MaxMsgBytes {
		return nil, 0, &Error{"reply too large"}
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, 0, &Error{"truncated reply"}
	}
	var r Reply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, &Error{"malformed reply"}
	}
	switch r.Kind() {
	case "fd_ok":
	case "err":
		msg, _ := r["error"].(string)
		return nil, 0, &Error{msg}
	default:
		return nil, 0, &Error{"unexpected reply: " + r.Kind()}
	}
	length, _ := r["len"].(float64)
	fd, err := recvFD(conn)
	if err != nil {
		return nil, 0, err
	}
	return os.NewFile(uintptr(fd), nm), int(length), nil
}

func recvFD(conn *net.UnixConn) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, &Error{"the credential service sent no descriptor"}
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, &Error{"malformed descriptor message"}
	}
	var fds []int
	for i := range msgs {
		if got, err := syscall.ParseUnixRights(&msgs[i]); err == nil {
			fds = append(fds, got...)
		}
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return -1, &Error{"the credential service sent no descriptor"}
	}
	syscall.CloseOnExec(fds[0])
	return fds[0], nil
}
