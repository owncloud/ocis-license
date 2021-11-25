package command

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/owncloud/ocis-license/internal/crypto"
	"github.com/owncloud/ocis-license/pkg/license"
	"github.com/urfave/cli/v2"
)

const (
	flagSigningKey  = "signing-key"
	flagSigningCert = "signing-cert"
	flagRootCert    = "root-cert"
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
		},
		Action: func(c *cli.Context) error {
			var (
				signingKeyPath  = c.String(flagSigningKey)
				signingCertPath = c.String(flagSigningCert)
			)

			signingCert, err := crypto.ReadCertificateFile(signingCertPath)
			if err != nil {
				return err
			}

			signingKey, err := crypto.ReadPrivateKeyFile(signingKeyPath)
			if err != nil {
				return err
			}

			l := license.New(
				license.Header{Version: "1"},
				license.Payload{
					ID:          uuid.NewString(),
					Created:     time.Now(),
					Environment: "development",
					Type:        "non-commercial",
					Features: []string{
						"core",
						"thumbnails",
						"reports",
					},
					Additional: map[string]interface{}{
						"key_origin": "someorigin",
					},
				},
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

			l := c.Args().First()

			_, err = license.Verify(strings.NewReader(l), *rootCert)
			if err != nil {
				fmt.Println("License is invalid")
			} else {
				fmt.Println("License is valid")
			}
			return nil
		},
	}
}
