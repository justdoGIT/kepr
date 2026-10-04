// Package kepr is a thin client for the kepr credential daemon.
//
// It speaks the CLI's wire format: one JSON request per connection,
// framed by a 4-byte big-endian length, over the per-user Unix socket.
// The daemon identifies the caller by socket credentials and applies the
// same rules as for the CLI (uid namespacing, audit, consent, sealed keys
// never returned). Go strings can't be wiped; keep values in scope briefly.
package kepr

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxMsgBytes is the daemon's frame limit.
const MaxMsgBytes = 65536

// Error is a refusal from the daemon or a transport failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// SocketPath resolves the socket the same way the CLI does.
func SocketPath() string {
	if os.Getenv("KEPR_SYSTEM_MODE") != "" {
		return "/run/kepr/kepr.sock"
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		home := os.Getenv("HOME")
		if home == "" {
			home = "/tmp"
		}
		runtime = filepath.Join(home, ".local/state/kepr/runtime")
	}
	return filepath.Join(runtime, "kepr", "kepr.sock")
}

// Client talks to one daemon socket.
type Client struct {
	Path    string
	Timeout time.Duration
}

// New returns a client for the default socket (65 s timeout covers the
// daemon's 60 s consent prompt).
func New() *Client { return &Client{Path: SocketPath(), Timeout: 65 * time.Second} }

// Reply is a decoded daemon response; Kind names its variant.
type Reply map[string]any

// Kind is the response variant, e.g. "get_ok".
func (r Reply) Kind() string { s, _ := r["kind"].(string); return s }

// Request sends one raw request (must include "cmd").
func (c *Client) Request(req map[string]any) (Reply, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxMsgBytes {
		return nil, &Error{"request too large"}
	}
	conn, err := net.DialTimeout("unix", c.Path, c.Timeout)
	if err != nil {
		return nil, &Error{fmt.Sprintf("cannot reach the credential service at %s (%v); start it with `kepr-daemon --user`", c.Path, err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := conn.Write(frame); err != nil {
		return nil, &Error{err.Error()}
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, &Error{"connection closed by the credential service"}
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMsgBytes {
		return nil, &Error{"reply too large"}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, &Error{"truncated reply"}
	}
	var r Reply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, &Error{"malformed reply"}
	}
	if r.Kind() == "err" {
		msg, _ := r["error"].(string)
		return nil, &Error{msg}
	}
	return r, nil
}

func (c *Client) expect(req map[string]any, kind string) (Reply, error) {
	r, err := c.Request(req)
	if err != nil {
		return nil, err
	}
	if r.Kind() != kind {
		if r.Kind() == "fido2_needed" {
			return nil, &Error{"this credential needs a FIDO2 touch; use `kepr get`"}
		}
		return nil, &Error{"unexpected reply: " + r.Kind()}
	}
	return r, nil
}

func upper(name string) (string, error) {
	if name == "" {
		return "", &Error{"credential name must not be empty"}
	}
	return strings.ToUpper(name), nil
}

// Get returns the value of name.
func (c *Client) Get(name string) (string, error) {
	n, err := upper(name)
	if err != nil {
		return "", err
	}
	r, err := c.expect(map[string]any{"cmd": "get", "name": n}, "get_ok")
	if err != nil {
		return "", err
	}
	v, _ := r["value"].(string)
	return v, nil
}

// SetOptions are the optional policy flags of Set.
type SetOptions struct {
	Generate        string // hex | base62 | pass | uuid | words (when value is empty)
	TTLSecs         uint64
	RequiresConsent bool
}

// Set stores value (or generates one when value is empty).
func (c *Client) Set(name, value string, o SetOptions) error {
	n, err := upper(name)
	if err != nil {
		return err
	}
	req := map[string]any{"cmd": "set", "name": n}
	if value != "" {
		req["value"] = value
	} else if o.Generate != "" {
		req["generate"] = o.Generate
	} else {
		req["generate"] = "hex"
	}
	if o.TTLSecs > 0 {
		req["ttl_secs"] = o.TTLSecs
	}
	if o.RequiresConsent {
		req["requires_consent"] = true
	}
	_, err = c.expect(req, "set_ok")
	return err
}

// Delete removes name.
func (c *Client) Delete(name string) error {
	n, err := upper(name)
	if err != nil {
		return err
	}
	_, err = c.expect(map[string]any{"cmd": "delete", "name": n}, "delete_ok")
	return err
}

// List returns credential records (no values).
func (c *Client) List() ([]any, error) {
	r, err := c.expect(map[string]any{"cmd": "list"}, "list_ok")
	if err != nil {
		return nil, err
	}
	l, _ := r["credentials"].([]any)
	return l, nil
}

// Restore makes history version (1 = newest) current again.
func (c *Client) Restore(name string, version int) error {
	n, err := upper(name)
	if err != nil {
		return err
	}
	_, err = c.expect(map[string]any{"cmd": "restore", "name": n, "version": version}, "restore_ok")
	return err
}

// SSHSign returns an OpenSSH signature blob over data; the key stays in the daemon.
func (c *Client) SSHSign(name string, data []byte) ([]byte, error) {
	n, err := upper(name)
	if err != nil {
		return nil, err
	}
	r, err := c.expect(map[string]any{"cmd": "sshsign", "name": n,
		"data_b64": base64.StdEncoding.EncodeToString(data)}, "ssh_sign_ok")
	if err != nil {
		return nil, err
	}
	s, _ := r["signature_b64"].(string)
	return base64.StdEncoding.DecodeString(s)
}

// Ping checks the daemon answers.
func (c *Client) Ping() error {
	_, err := c.expect(map[string]any{"cmd": "ping"}, "pong")
	return err
}

// IsRefusal reports whether err came from the daemon (not the transport).
func IsRefusal(err error) bool { var e *Error; return errors.As(err, &e) }
