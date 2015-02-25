package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"code.google.com/p/go.net/context"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/distribution/configuration"
	"github.com/docker/distribution/registry/handlers"
	_ "github.com/docker/distribution/registry/storage/driver/filesystem"
	_ "github.com/openshift/openshift-v2-docker-registry/pkg/repository"
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("usage: registry <config>")
		os.Exit(1)
	}

	configPath := flag.Arg(0)
	configFile, err := os.Open(configPath)
	if err != nil {
		log.Fatalf("Unable to open configuration file: %s", err)
	}
	config, err := configuration.Parse(configFile)
	if err != nil {
		log.Fatalf("Error parsing configuration file: %s", err)
	}

	logLevel, err := log.ParseLevel(string(config.Loglevel))
	if err != nil {
		log.Errorf("Error parsing log level %q: %s", config.Loglevel, err)
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)

	ctx := context.Background()
	app := handlers.NewApp(ctx, *config)
	if err := http.ListenAndServe(config.HTTP.Addr, app); err != nil {
		log.Fatalf("Error listening: %s", err)
	}
}
