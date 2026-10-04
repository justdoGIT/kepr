package kepr

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func fakeDaemon(t *testing.T, reply func(map[string]any) map[string]any) (string, *[]map[string]any) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seen := &[]map[string]any{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var hdr [4]byte
			io.ReadFull(c, hdr[:])
			body := make([]byte, binary.BigEndian.Uint32(hdr[:]))
			io.ReadFull(c, body)
			var req map[string]any
			json.Unmarshal(body, &req)
			*seen = append(*seen, req)
			out, _ := json.Marshal(reply(req))
			frame := make([]byte, 4+len(out))
			binary.BigEndian.PutUint32(frame, uint32(len(out)))
			copy(frame[4:], out)
			c.Write(frame)
			c.Close()
		}
	}()
	return p, seen
}

func TestGetUppercasesAndReturnsValue(t *testing.T) {
	p, seen := fakeDaemon(t, func(r map[string]any) map[string]any {
		return map[string]any{"kind": "get_ok", "name": r["name"], "value": "v1"}
	})
	c := &Client{Path: p, Timeout: time.Second}
	v, err := c.Get("api_key")
	if err != nil || v != "v1" {
		t.Fatalf("got %q %v", v, err)
	}
	if want := (map[string]any{"cmd": "get", "name": "API_KEY"}); !reflect.DeepEqual((*seen)[0], want) {
		t.Fatalf("sent %v", (*seen)[0])
	}
}

func TestErrReplyIsARefusal(t *testing.T) {
	p, _ := fakeDaemon(t, func(map[string]any) map[string]any {
		return map[string]any{"kind": "err", "error": "credential unavailable"}
	})
	_, err := (&Client{Path: p, Timeout: time.Second}).Get("SEALED")
	if err == nil || !IsRefusal(err) || err.Error() != "credential unavailable" {
		t.Fatalf("err = %v", err)
	}
}

func TestSetBuildsFlags(t *testing.T) {
	p, seen := fakeDaemon(t, func(r map[string]any) map[string]any {
		return map[string]any{"kind": "set_ok", "name": r["name"], "cred_name": "x", "password_protected": false}
	})
	err := (&Client{Path: p, Timeout: time.Second}).Set("k", "", SetOptions{Generate: "words", TTLSecs: 60, RequiresConsent: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"cmd": "set", "name": "K", "generate": "words", "ttl_secs": 60.0, "requires_consent": true}
	if !reflect.DeepEqual((*seen)[0], want) {
		t.Fatalf("sent %v", (*seen)[0])
	}
}

func TestUnreachableAndBadName(t *testing.T) {
	if err := (&Client{Path: "/nonexistent/kepr.sock", Timeout: time.Second}).Ping(); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := (&Client{Path: "/x"}).Get(""); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestSocketPath(t *testing.T) {
	t.Setenv("KEPR_SYSTEM_MODE", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := SocketPath(); got != "/run/user/1000/kepr/kepr.sock" {
		t.Fatal(got)
	}
	t.Setenv("KEPR_SYSTEM_MODE", "1")
	if got := SocketPath(); got != "/run/kepr/kepr.sock" {
		t.Fatal(got)
	}
}

func TestLiveRoundTrip(t *testing.T) {
	if os.Getenv("KEPR_SDK_LIVE") == "" {
		t.Skip("set KEPR_SDK_LIVE=1 with a running daemon")
	}
	c := New()
	name := "GO_SDK_" + strconv.Itoa(os.Getpid())
	if err := c.Set(name, "one", SetOptions{}); err != nil {
		t.Fatal(err)
	}
	defer c.Delete(name)
	c.Set(name, "two", SetOptions{})
	if err := c.Restore(name, 1); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Get(name); v != "one" {
		t.Fatalf("got %q", v)
	}
}
