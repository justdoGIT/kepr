package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// WriteFiles writes files under target the way the driver does: each one
// to a temporary file with its mode, then renamed into place, so a reader
// never sees a partial value. Paths must stay inside target.
func WriteFiles(target string, files []*v1alpha1.File) error {
	if target == "" {
		return fmt.Errorf("target path: empty")
	}
	for _, f := range files {
		dst := filepath.Join(target, filepath.FromSlash(f.GetPath()))
		if rel, err := filepath.Rel(target, dst); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%s: outside the target path", f.GetPath())
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("%s: %v", f.GetPath(), err)
		}
		mode := os.FileMode(f.GetMode()) & os.ModePerm
		tmp, err := os.CreateTemp(filepath.Dir(dst), ".kepr-*")
		if err != nil {
			return fmt.Errorf("%s: %v", f.GetPath(), err)
		}
		name := tmp.Name()
		_, werr := tmp.Write(f.GetContents())
		cerr := tmp.Close()
		if err := firstErr(werr, cerr, os.Chmod(name, mode)); err != nil {
			os.Remove(name)
			return fmt.Errorf("%s: %v", f.GetPath(), err)
		}
		if err := os.Rename(name, dst); err != nil {
			os.Remove(name)
			return fmt.Errorf("%s: %v", f.GetPath(), err)
		}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
