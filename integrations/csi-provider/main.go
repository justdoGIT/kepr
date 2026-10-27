// Command kepr-csi-provider is a Secrets Store CSI driver provider that
// mounts credentials from kepr-eso-provider (plan T10.08).
//
// It serves the v1alpha1.CSIDriverProvider gRPC service on a Unix socket
// in the driver's provider directory (one DaemonSet pod per node).
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/justdoGIT/kepr/integrations/csi-provider/internal/provider"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	socket := flag.String("endpoint", "/var/run/secrets-store-csi-providers/kepr.sock", "Unix socket the driver connects to")
	url := flag.String("kepr-url", "http://kepr-eso-provider:8080", "kepr-eso-provider base URL (a SecretProviderClass `url` overrides it)")
	tokenFile := flag.String("token-file", "", "bearer token for kepr-eso-provider, when the volume has no nodePublishSecretRef")
	writeFiles := flag.Bool("write-files", false, "also write files under the target path (drivers before v0.0.21)")
	flag.Parse()

	_ = os.Remove(*socket)
	lis, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("listen %s: %v", *socket, err)
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		log.Fatalf("chmod %s: %v", *socket, err)
	}
	srv := provider.New(&http.Client{Timeout: 30 * time.Second}, *url, *tokenFile, version)
	srv.WriteFiles = *writeFiles
	g := grpc.NewServer()
	v1alpha1.RegisterCSIDriverProviderServer(g, srv)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		g.GracefulStop()
	}()
	log.Printf("kepr-csi-provider %s listening on %s", version, *socket)
	if err := g.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
