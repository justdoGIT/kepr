package provider

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var store = map[string]string{
	"DB_URL":  "postgres://u:p@db/app",
	"API_KEY": "sk-test-123",
}

// fakeESO stands in for kepr-eso-provider's POST /v1/secrets.
func fakeESO(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/secrets" {
			http.NotFound(w, r)
			return
		}
		want := ""
		if token != "" {
			want = "Bearer " + token // "" = kepr-eso-provider without a token
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		var req struct{ Keys []string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		out := map[string]map[string]string{"secrets": {}, "errors": {}}
		for _, k := range req.Keys {
			if v, ok := store[k]; ok {
				out["secrets"][k] = v
			} else {
				out["errors"][k] = "daemon error: credential unavailable"
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func mountReq(t *testing.T, attrs map[string]string, secrets map[string]string, perm string) *v1alpha1.MountRequest {
	t.Helper()
	a, _ := json.Marshal(attrs)
	s, _ := json.Marshal(secrets)
	return &v1alpha1.MountRequest{Attributes: string(a), Secrets: string(s), TargetPath: t.TempDir(), Permission: perm}
}

func TestMountWritesFilesWithTheRightModes(t *testing.T) {
	eso := fakeESO(t, "t0k")
	defer eso.Close()
	s := New(eso.Client(), eso.URL, "", "test")
	req := mountReq(t, map[string]string{
		"objects":                          "DB_URL\n- api_key=api/key.txt",
		"csi.storage.k8s.io/pod.name":      "web-0",
		"csi.storage.k8s.io/pod.namespace": "default",
	}, map[string]string{"token": "t0k"}, "288") // 0440, as the driver encodes it
	resp, err := s.Mount(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"DB_URL": store["DB_URL"], "api/key.txt": store["API_KEY"]}
	if len(resp.Files) != 2 {
		t.Fatalf("files: %v", resp.Files)
	}
	for _, f := range resp.Files {
		if want[f.Path] != string(f.Contents) || f.Mode != 0o440 {
			t.Errorf("%s: mode %o contents %q", f.Path, f.Mode, f.Contents)
		}
	}
	for _, v := range resp.ObjectVersion {
		if !strings.HasPrefix(v.Id, "kepr/") || len(v.Version) != 24 || strings.Contains(v.Version, "sk-test") {
			t.Errorf("object version %v", v)
		}
	}
	// What the driver then does with them (and -write-files does itself).
	if err := WriteFiles(req.TargetPath, resp.Files); err != nil {
		t.Fatal(err)
	}
	for p, v := range want {
		fi, err := os.Stat(filepath.Join(req.TargetPath, p))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o440 {
			t.Errorf("%s: mode %o", p, fi.Mode().Perm())
		}
		b, _ := os.ReadFile(filepath.Join(req.TargetPath, p))
		if string(b) != v {
			t.Errorf("%s: %q", p, b)
		}
	}
	leftovers, _ := filepath.Glob(filepath.Join(req.TargetPath, "*", ".kepr-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
}

func TestFileModeOverrideAndWriteFilesFlag(t *testing.T) {
	eso := fakeESO(t, "")
	defer eso.Close()
	s := New(eso.Client(), eso.URL, "", "test")
	s.WriteFiles = true
	req := mountReq(t, map[string]string{"objects": "API_KEY=key", "fileMode": "0400"}, nil, "420")
	if _, err := s.Mount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(req.TargetPath, "key"))
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("key: %v %v", fi, err)
	}
}

func TestTokenFromFile(t *testing.T) {
	eso := fakeESO(t, "from-file")
	defer eso.Close()
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(eso.Client(), eso.URL, tf, "test")
	if _, err := s.Mount(context.Background(), mountReq(t, map[string]string{"objects": "DB_URL"}, nil, "")); err != nil {
		t.Fatal(err)
	}
}

func TestMountFailuresNameCredentialsNotValues(t *testing.T) {
	eso := fakeESO(t, "t0k")
	defer eso.Close()
	s := New(eso.Client(), eso.URL, "", "test")
	tok := map[string]string{"token": "t0k"}
	cases := []struct {
		attrs   map[string]string
		secrets map[string]string
		code    codes.Code
		want    string
	}{
		{map[string]string{"objects": "DB_URL,NOPE"}, tok, codes.Unavailable, "unavailable: NOPE"},
		{map[string]string{"objects": "DB_URL"}, map[string]string{"token": "wrong"}, codes.Unavailable, "HTTP 401"},
		{map[string]string{"objects": ""}, tok, codes.InvalidArgument, "none given"},
		{map[string]string{"objects": "DB-URL"}, tok, codes.InvalidArgument, "not a credential name"},
		{map[string]string{"objects": "DB_URL=../etc/x"}, tok, codes.InvalidArgument, "relative and clean"},
		{map[string]string{"objects": "DB_URL=/abs"}, tok, codes.InvalidArgument, "relative and clean"},
		{map[string]string{"objects": "DB_URL=a,API_KEY=a"}, tok, codes.InvalidArgument, "two objects"},
		{map[string]string{"objects": "DB_URL", "fileMode": "999"}, tok, codes.InvalidArgument, "fileMode"},
		{map[string]string{"objects": "DB_URL", "url": "file:///etc"}, tok, codes.InvalidArgument, "url"},
	}
	for _, c := range cases {
		_, err := s.Mount(context.Background(), mountReq(t, c.attrs, c.secrets, ""))
		st, _ := status.FromError(err)
		if st.Code() != c.code || !strings.Contains(st.Message(), c.want) {
			t.Errorf("%v: got %v", c.attrs, err)
		}
		if err != nil && (strings.Contains(err.Error(), store["DB_URL"]) || strings.Contains(err.Error(), "t0k")) {
			t.Errorf("error leaks a secret: %v", err)
		}
	}
	if err := WriteFiles(t.TempDir(), []*v1alpha1.File{{Path: "../x"}}); err == nil {
		t.Error("WriteFiles accepted a path outside the target")
	}
}

// The real wire: gRPC over a Unix socket, as the driver connects.
func TestGRPCOverUnixSocket(t *testing.T) {
	eso := fakeESO(t, "t0k")
	defer eso.Close()
	sock := filepath.Join(t.TempDir(), "kepr.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	v1alpha1.RegisterCSIDriverProviderServer(g, New(eso.Client(), eso.URL, "", "1.2.3"))
	go func() { _ = g.Serve(lis) }()
	defer g.Stop()
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := v1alpha1.NewCSIDriverProviderClient(conn)
	v, err := c.Version(context.Background(), &v1alpha1.VersionRequest{Version: "v1alpha1"})
	if err != nil || v.RuntimeName != "kepr" || v.RuntimeVersion != "1.2.3" {
		t.Fatalf("version: %v %v", v, err)
	}
	resp, err := c.Mount(context.Background(), mountReq(t, map[string]string{"objects": "API_KEY"}, map[string]string{"token": "t0k"}, "420"))
	if err != nil || len(resp.Files) != 1 || string(resp.Files[0].Contents) != store["API_KEY"] || resp.Files[0].Mode != 0o644 {
		t.Fatalf("mount: %v %v", resp, err)
	}
}

func TestParsing(t *testing.T) {
	objs, err := ParseObjects(" db_url , API_KEY=dir/k\n\n")
	if err != nil || len(objs) != 2 || objs[0] != (Object{"DB_URL", "DB_URL"}) || objs[1] != (Object{"API_KEY", "dir/k"}) {
		t.Fatalf("%v %v", objs, err)
	}
	many := strings.Repeat("A,", MaxObjects) + "B"
	if _, err := ParseObjects(many); err == nil {
		t.Error("over the batch limit")
	}
	for perm, want := range map[string]os.FileMode{"": 0o644, "420": 0o644, "256": 0o400} {
		if m, err := FileMode(perm, ""); err != nil || m != want {
			t.Errorf("%q: %o %v", perm, m, err)
		}
	}
	if _, err := FileMode("2147484159", ""); err == nil {
		t.Error("directory bit accepted")
	}
}
