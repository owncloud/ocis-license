package main

import (
	"log"
	"os"

	"github.com/owncloud/ocis-license/internal/command"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			command.Certificate(),
			command.License(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
