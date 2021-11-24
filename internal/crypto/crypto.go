// Package crypto provides utility functions for
// generating and handling certificates and key pairs.
//
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"time"
)

var (
	errInvalidContent = errors.New("invalid content")
)

// GenerateRootCA generates a new ed25519 keypair and returns a self signed
// certificate and the private key.
//
// If the generation of the keypair or the creation of the certificate fails
// an error is returned.
//
// The generated certificate has the serial number '1' and is valid for 10 years.
func GenerateRootCA(subject string) ([]byte, ed25519.PrivateKey, error) {
	notBefore := time.Now()
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, crt, crt, pubkey, privkey)
	if err != nil {
		return nil, nil, err
	}

	return caBytes, privkey, nil
}

// GenerateIntermediateCA generates a new ed25519 keypair and returns a
// certificate signed by the provided parent.
//
// If the generation of the keypair or the creation of the certificate fails
// an error is returned.
func GenerateIntermediateCA(serialNumber big.Int, issuer, subject string, notBefore, notAfter time.Time, parentCrt x509.Certificate, parentPrivKey ed25519.PrivateKey) ([]byte, ed25519.PrivateKey, error) {
	crt := &x509.Certificate{
		SerialNumber: &serialNumber,
		Issuer: pkix.Name{
			CommonName: issuer,
		},
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, crt, &parentCrt, pubkey, parentPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return caBytes, privkey, nil
}

// WriteCertificateFile pem encodes the certificate and writes it to the path.
func WriteCertificateFile(crt []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return WriteCertificate(crt, file)
}

// WriteCertificate pem encodes the certificate and writes it to dst.
func WriteCertificate(crt []byte, dst io.Writer) error {
	return pem.Encode(dst, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt,
	})
}

// WritePrivateKeyFile pem encodes the private key and writes it to the path.
func WritePrivateKeyFile(key ed25519.PrivateKey, path string) error {
	// file, err := os.Create(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return WritePrivateKey(key, file)
}

// WritePrivateKey pem encodes the private key and writes it to dst.
func WritePrivateKey(key ed25519.PrivateKey, dst io.Writer) error {
	// We can safely ignore the error here since we know that we pass in a ed25519.PrivateKey
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.Encode(dst, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

// ReadCertificateFile reads the certificate from the path.
func ReadCertificateFile(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ReadCertificate(f)
}

// ReadCertificate reads the certificate from the reader.
func ReadCertificate(r io.Reader) (*x509.Certificate, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	p, _ := pem.Decode(buf.Bytes())
	if p == nil {
		return nil, errInvalidContent
	}

	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

// ReadPrivateKeyFile reads the private key from the path.
func ReadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKey(f)
}

// ReadPrivateKey reads the private key from the reader.
func ReadPrivateKey(r io.Reader) (ed25519.PrivateKey, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	pKey, _ := pem.Decode(buf.Bytes())
	if pKey == nil {
		return nil, errInvalidContent
	}

	privkey, err := x509.ParsePKCS8PrivateKey(pKey.Bytes)
	if err != nil {
		return nil, err
	}

	return privkey.(ed25519.PrivateKey), nil
}
