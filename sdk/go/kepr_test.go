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
	"syscall"
	"testing"
	"time"
)

func fakeDaemon(t *testing.T, reply func(map[string]any) map[string]any) (string, *[]map[string]any) {
	t.Helper()
	return fakeDaemonAfter(t, reply, nil)
}

// fakeDaemonAfter also calls after(conn) once the reply frame is written
// (e.g. to pass a descriptor).
func fakeDaemonAfter(t *testing.T, reply func(map[string]any) map[string]any, after func(*net.UnixConn)) (string, *[]map[string]any) {
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
			if after != nil {
				after(c.(*net.UnixConn))
			}
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

func setOK(r map[string]any) map[string]any {
	return map[string]any{"kind": "set_ok", "name": r["name"], "cred_name": "x", "password_protected": false}
}

func TestSetValueGenerateAndValidation(t *testing.T) {
	p, seen := fakeDaemon(t, setOK)
	c := &Client{Path: p, Timeout: time.Second}
	if err := c.Set("a", "v", SetOptions{RequiresFIDO2: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Generate("b", "base62", SetOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"cmd": "set", "name": "A", "value": "v", "requires_fido2": true},
		{"cmd": "set", "name": "B", "generate": "base62"},
	}
	if !reflect.DeepEqual(*seen, want) {
		t.Fatalf("sent %v", *seen)
	}
	if err := c.Generate("c", "rot13", SetOptions{}); err == nil {
		t.Fatal("unknown generate kind accepted")
	}
	if err := c.Set("c", "v", SetOptions{Generate: "hex"}); err == nil {
		t.Fatal("value and generate together accepted")
	}
	if len(*seen) != 2 {
		t.Fatalf("invalid calls reached the daemon: %v", *seen)
	}
}

func TestDeleteCredentialsAndInfo(t *testing.T) {
	creds := []any{
		map[string]any{"name": "GH", "cred_name": "kepr-1-gh", "size": 40, "modified": "2026-10-01 12:00",
			"expires_at": "2026-12-01 00:00", "requires_consent": true},
		map[string]any{"name": "OA", "cred_name": "kepr-1-oa", "size": 9, "modified": "2026-10-02 08:00",
			"sealed": true, "bound_hosts": []string{"api.openai.com"}, "tags": []string{"work"}},
	}
	p, seen := fakeDaemon(t, func(r map[string]any) map[string]any {
		if r["cmd"] == "delete" {
			return map[string]any{"kind": "delete_ok", "name": r["name"]}
		}
		return map[string]any{"kind": "list_ok", "credentials": creds, "count": 2}
	})
	c := &Client{Path: p, Timeout: time.Second}
	if err := c.Delete("gh"); err != nil {
		t.Fatal(err)
	}
	if want := (map[string]any{"cmd": "delete", "name": "GH"}); !reflect.DeepEqual((*seen)[0], want) {
		t.Fatalf("sent %v", (*seen)[0])
	}
	infos, err := c.Credentials()
	if err != nil || len(infos) != 2 {
		t.Fatalf("%v %v", infos, err)
	}
	if infos[0].ExpiresAt != "2026-12-01 00:00" || !infos[0].RequiresConsent || infos[0].Sealed {
		t.Fatalf("%+v", infos[0])
	}
	if !infos[1].Sealed || infos[1].BoundHosts[0] != "api.openai.com" || infos[1].Tags[0] != "work" {
		t.Fatalf("%+v", infos[1])
	}
	if i, err := c.Info("oa"); err != nil || i == nil || i.Name != "OA" {
		t.Fatalf("%v %v", i, err)
	}
	if i, err := c.Info("missing"); err != nil || i != nil {
		t.Fatalf("%v %v", i, err)
	}
}

func TestFetchFDReceivesADescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("s3cret"))
	w.Close()
	defer r.Close()
	p, seen := fakeDaemonAfter(t, func(map[string]any) map[string]any {
		return map[string]any{"kind": "fd_ok", "len": 6}
	}, func(c *net.UnixConn) {
		c.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(r.Fd())), nil)
	})
	f, n, err := (&Client{Path: p, Timeout: time.Second}).FetchFD("db_pass")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if want := (map[string]any{"cmd": FetchFDCmd, "name": "DB_PASS"}); !reflect.DeepEqual((*seen)[0], want) {
		t.Fatalf("sent %v", (*seen)[0])
	}
	got, _ := io.ReadAll(f)
	if n != 6 || string(got) != "s3cret" {
		t.Fatalf("n=%d got=%q", n, got)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("received fd is inheritable")
	}
}

func TestFetchFDWithoutDescriptorFails(t *testing.T) {
	p, _ := fakeDaemon(t, func(map[string]any) map[string]any {
		return map[string]any{"kind": "fd_ok", "len": 6}
	})
	if _, _, err := (&Client{Path: p, Timeout: time.Second}).FetchFD("X"); err == nil {
		t.Fatal("expected an error")
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
