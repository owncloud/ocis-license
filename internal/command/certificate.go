package command

import (
	"fmt"
	"time"

	"github.com/owncloud/ocis-license/internal/crypto"
	"github.com/urfave/cli/v2"
)

const (
	profileRootCa         = "root-ca"
	profileIntermediateCa = "intermediate-ca"

	flagProfile = "profile"
	flagCa      = "ca"
	flagCaKey   = "ca-key"
)

func Certificate() *cli.Command {
	return &cli.Command{
		Name:    "certificate",
		Aliases: []string{"cert"},
		Subcommands: []*cli.Command{
			createCertSubCommand(),
		},
	}
}

func createCertSubCommand() *cli.Command {
	return &cli.Command{
		Name: "create",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     flagProfile,
				Usage:    "the profile of the certificate",
				Required: true,
			},
			&cli.StringFlag{
				Name:  flagCa,
				Usage: "the parent ca certificate",
			},
			&cli.StringFlag{
				Name:  flagCaKey,
				Usage: "the parent ca key",
			},
		},
		Usage:     "create a certificate",
		UsageText: "./ocis-license certificate create <subject> <crt-file> <key-file> [--profile=<profile>]",
		Action: func(c *cli.Context) error {
			if c.NArg() != 3 {
				fmt.Println(c.Command.UsageText)
				return nil
			}
			var (
				profile = c.String(flagProfile)
				subject = c.Args().Get(0)
				crtFile = c.Args().Get(1)
				keyFile = c.Args().Get(2)
			)
			switch profile {
			case profileRootCa:
				crt, privkey, err := crypto.GenerateRootCA(subject, subject)
				if err != nil {
					return err
				}

				if err := crypto.WriteCertificateFile(crt, crtFile); err != nil {
					return err
				}

				if err := crypto.WritePrivateKeyFile(privkey, keyFile); err != nil {
					return err
				}
			case profileIntermediateCa:
				var (
					parentCrtPath = c.String(flagCa)
					parentKeyPath = c.String(flagCaKey)
				)

				parentCrt, err := crypto.ReadCertificateFile(parentCrtPath)
				if err != nil {
					return err
				}

				parentPrivKey, err := crypto.ReadPrivateKeyFile(parentKeyPath)
				if err != nil {
					return err
				}

				crt, privkey, err := crypto.GenerateIntermediateCA(subject, subject, time.Now(), time.Now().AddDate(10, 0, 0), *parentCrt, parentPrivKey)
				if err != nil {
					return err
				}

				if err := crypto.WriteCertificateFile(crt, crtFile); err != nil {
					return err
				}

				if err := crypto.WritePrivateKeyFile(privkey, keyFile); err != nil {
					return err
				}

			}
			return nil
		},
	}
}
