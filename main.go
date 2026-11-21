package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/alexandrosnt/terraform-provider-certloom/internal/provider"
)

// version is set at release time by GoReleaser.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers such as delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/alexandrosnt/certloom",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
