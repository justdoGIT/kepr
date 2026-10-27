// Package provider implements the Secrets Store CSI driver's provider
// service (sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1) on top
// of kepr-eso-provider's HTTP API (plan T10.08).
//
// A SecretProviderClass names the credentials to mount:
//
//	parameters:
//	  url: http://kepr-eso-provider.kepr.svc:8080   # optional; else -kepr-url
//	  objects: |
//	    DB_URL
//	    API_KEY=api/key.txt
//	  fileMode: "0400"                              # optional; else the volume's filePermission
//
// The bearer token for kepr-eso-provider comes from the volume's
// nodePublishSecretRef (key "token") or, failing that, -token-file. Values
// are fetched in one batch and returned as files for the driver to write;
// a Mount either gets every object or fails. Errors name credentials,
// never values.
package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// MaxObjects matches kepr-eso-provider's batch limit.
const MaxObjects = 100

// maxBody bounds the HTTP response read from kepr-eso-provider.
const maxBody = 8 << 20

// Server is the CSIDriverProvider gRPC service.
type Server struct {
	v1alpha1.UnimplementedCSIDriverProviderServer

	HTTP       *http.Client
	DefaultURL string
	TokenFile  string
	// WriteFiles also writes the files under the target path itself (for
	// drivers older than v0.0.21 that do not write returned files).
	WriteFiles     bool
	RuntimeVersion string

	versionKey []byte
}

// New returns a Server with a per-process key for object versions.
func New(client *http.Client, defaultURL, tokenFile, version string) *Server {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Server{HTTP: client, DefaultURL: defaultURL, TokenFile: tokenFile, RuntimeVersion: version, versionKey: key}
}

// Object is one credential and the file it is written to.
type Object struct {
	Name string
	Path string
}

// ValidName is kepr's credential-name rule (A-Z, 0-9, _; at most 128).
func ValidName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for _, c := range n {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ParseObjects reads `NAME` or `NAME=relative/path` entries, one per line
// or comma separated.
func ParseObjects(s string) ([]Object, error) {
	var out []Object
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
		f = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f), "- "))
		if f == "" {
			continue
		}
		name, p, _ := strings.Cut(f, "=")
		name = strings.ToUpper(strings.TrimSpace(name))
		p = strings.TrimSpace(p)
		if p == "" {
			p = name
		}
		if !ValidName(name) {
			return nil, fmt.Errorf("objects: not a credential name: %q", name)
		}
		if p != path.Clean(p) || path.IsAbs(p) || p == "." || strings.HasPrefix(p, "../") || p == ".." {
			return nil, fmt.Errorf("objects: %s: path must be relative and clean: %q", name, p)
		}
		if seen[p] {
			return nil, fmt.Errorf("objects: two objects write %q", p)
		}
		seen[p] = true
		out = append(out, Object{Name: name, Path: p})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("objects: none given")
	}
	if len(out) > MaxObjects {
		return nil, fmt.Errorf("objects: at most %d per volume", MaxObjects)
	}
	return out, nil
}

// FileMode is the `fileMode` parameter (octal) or else the driver's
// `permission` (a JSON-encoded os.FileMode); 0644 when neither is set.
func FileMode(permission, override string) (os.FileMode, error) {
	if override != "" {
		m, err := strconv.ParseUint(override, 8, 32)
		if err != nil || m > 0o777 {
			return 0, fmt.Errorf("fileMode: not an octal permission: %q", override)
		}
		return os.FileMode(m), nil
	}
	if permission == "" {
		return 0o644, nil
	}
	var m os.FileMode
	if err := json.Unmarshal([]byte(permission), &m); err != nil || m&^os.ModePerm != 0 {
		return 0, fmt.Errorf("permission: not a file mode: %q", permission)
	}
	return m, nil
}

// Version implements v1alpha1.CSIDriverProviderServer.
func (s *Server) Version(context.Context, *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return &v1alpha1.VersionResponse{Version: "v1alpha1", RuntimeName: "kepr", RuntimeVersion: s.RuntimeVersion}, nil
}

// Mount implements v1alpha1.CSIDriverProviderServer.
func (s *Server) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {
	attrs := map[string]string{}
	if err := json.Unmarshal([]byte(req.GetAttributes()), &attrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "attributes: %v", err)
	}
	secrets := map[string]string{}
	if req.GetSecrets() != "" {
		if err := json.Unmarshal([]byte(req.GetSecrets()), &secrets); err != nil {
			return nil, status.Error(codes.InvalidArgument, "secrets: not a JSON object")
		}
	}
	objs, err := ParseObjects(attrs["objects"])
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	mode, err := FileMode(req.GetPermission(), attrs["fileMode"])
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	base := attrs["url"]
	if base == "" {
		base = s.DefaultURL
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil, status.Errorf(codes.InvalidArgument, "url: need http:// or https://, got %q", base)
	}
	token, err := s.token(secrets)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	values, err := s.fetch(ctx, strings.TrimRight(base, "/"), token, objs)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	resp := &v1alpha1.MountResponse{}
	for _, o := range objs {
		v := []byte(values[o.Name])
		resp.Files = append(resp.Files, &v1alpha1.File{Path: o.Path, Mode: int32(mode), Contents: v})
		resp.ObjectVersion = append(resp.ObjectVersion, &v1alpha1.ObjectVersion{Id: "kepr/" + o.Name, Version: s.version(o.Name, v)})
	}
	if s.WriteFiles {
		if err := WriteFiles(req.GetTargetPath(), resp.Files); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return resp, nil
}

func (s *Server) token(secrets map[string]string) (string, error) {
	if t := strings.TrimSpace(secrets["token"]); t != "" {
		return t, nil
	}
	if s.TokenFile == "" {
		return "", nil // kepr-eso-provider decides whether that is allowed
	}
	b, err := os.ReadFile(s.TokenFile)
	if err != nil {
		return "", fmt.Errorf("token file: %v", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// version is an opaque per-process HMAC, so the driver sees changes
// without a plain hash of the value landing in the pod status.
func (s *Server) version(name string, v []byte) string {
	m := hmac.New(sha256.New, s.versionKey)
	m.Write([]byte(name))
	m.Write([]byte{0})
	m.Write(v)
	return hex.EncodeToString(m.Sum(nil)[:12])
}

type batchResponse struct {
	Secrets map[string]string `json:"secrets"`
	Errors  map[string]string `json:"errors"`
}

func (s *Server) fetch(ctx context.Context, base, token string, objs []Object) (map[string]string, error) {
	keys := make([]string, len(objs))
	for i, o := range objs {
		keys[i] = o.Name
	}
	body, _ := json.Marshal(map[string][]string{"keys": keys})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/secrets", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kepr-eso-provider: %v", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	if token != "" {
		hreq.Header.Set("Authorization", "Bearer "+token)
	}
	hresp, err := s.HTTP.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("kepr-eso-provider unreachable: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kepr-eso-provider: HTTP %d", hresp.StatusCode)
	}
	var br batchResponse
	if err := json.NewDecoder(io.LimitReader(hresp.Body, maxBody)).Decode(&br); err != nil {
		return nil, fmt.Errorf("kepr-eso-provider: bad response")
	}
	var missing []string
	for _, k := range keys {
		if _, ok := br.Secrets[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("kepr-eso-provider: unavailable: %s", strings.Join(missing, ", "))
	}
	return br.Secrets, nil
}
