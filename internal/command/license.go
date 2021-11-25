package command

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/owncloud/ocis-license/internal/crypto"
	"github.com/owncloud/ocis-license/pkg/license"
	"github.com/urfave/cli/v2"
)

const (
	flagSigningKey      = "signing-key"
	flagSigningCert     = "signing-cert"
	flagRootCert        = "root-cert"
	flagPayloadTemplate = "payload-template"
)

func License() *cli.Command {
	return &cli.Command{
		Name: "license",
		Subcommands: []*cli.Command{
			createLicenseSubcommand(),
			verifyLicenseSubCommand(),
		},
	}
}

func createLicenseSubcommand() *cli.Command {
	return &cli.Command{
		Name: "create",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  flagSigningKey,
				Usage: "path to the key used to sign the license",
			},
			&cli.StringFlag{
				Name:  flagSigningCert,
				Usage: "path to the cert corresponding to the signing key",
			},
			&cli.StringFlag{
				Name:  flagPayloadTemplate,
				Usage: "path to the payload template",
			},
		},
		Action: func(c *cli.Context) error {
			var (
				signingKeyPath  = c.String(flagSigningKey)
				signingCertPath = c.String(flagSigningCert)

				payloadTemplatePath = c.String(flagPayloadTemplate)
			)

			signingCert, err := crypto.ReadCertificateFile(signingCertPath)
			if err != nil {
				return err
			}

			signingKey, err := crypto.ReadPrivateKeyFile(signingKeyPath)
			if err != nil {
				return err
			}

			payloadTemplate, err := os.ReadFile(payloadTemplatePath)
			if err != nil {
				return err
			}

			var payload license.Payload
			err = json.Unmarshal(payloadTemplate, &payload)
			if err != nil {
				return err
			}

			l := license.New(
				license.Header{Version: "1"},
				payload,
			)

			err = license.Sign(&l, *signingCert, signingKey)
			if err != nil {
				return err
			}

			encoded, err := l.EncodeToString()
			if err != nil {
				return err
			}
			fmt.Println(encoded)

			return nil
		},
	}
}

func verifyLicenseSubCommand() *cli.Command {
	return &cli.Command{
		Name: "verify",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  flagRootCert,
				Usage: "path to the root cert",
			},
		},
		Action: func(c *cli.Context) error {
			var (
				rootCertPath = c.String(flagRootCert)
			)

			rootCert, err := crypto.ReadCertificateFile(rootCertPath)
			if err != nil {
				return err
			}

			licenseStr := c.Args().First()

			_, err = license.Verify(strings.NewReader(licenseStr), *rootCert)
			if err != nil {
				fmt.Println(color.RedString("X"), "License is", color.RedString("invalid"))
			} else {
				fmt.Println(color.GreenString("✓"), "License is", color.GreenString("valid"))
			}
			return nil
		},
	}
}
