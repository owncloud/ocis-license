package command

import (
	"fmt"
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
		},
	}
}

func createLicenseSubcommand() *cli.Command {
	return &cli.Command{
		Name: "create",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  flagSigningKey,
				Usage: "the key used to sign the license",
			},
			&cli.StringFlag{
				Name:  flagSigningCert,
				Usage: "the cert corresponding to the signing key",
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

			payload := license.NewPayload()
			id, err := uuid.NewUUID()
			if err != nil {
				return err
			}
			payload.ID = id.String()
			payload.Created = time.Now()
			payload.Environment = "development"
			payload.Type = "non-commercial"

			l := license.License{
				Header:  license.Header{Version: "1"},
				Payload: payload,
			}

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
