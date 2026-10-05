// Command terraform-provider-kepr is a Terraform provider for the local
// kepr credential daemon (plan T8.03).
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/justdoGIT/kepr/integrations/terraform-provider-kepr/internal/provider"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/justdogit/kepr",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
