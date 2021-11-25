package main

import (
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/owncloud/ocis-license/internal/command"
	"github.com/urfave/cli/v2"
)

const (
	flagNoColor = "no-color"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			command.Certificate(),
			command.License(),
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  flagNoColor,
				Value: false,
				Usage: "Disable color output",
			},
		},
		Before: func(c *cli.Context) error {
			disableColorOutput := c.Bool(flagNoColor)
			if disableColorOutput {
				color.NoColor = true
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
