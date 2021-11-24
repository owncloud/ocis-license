package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"
)

func GenerateRootCA(issuer, subject string) ([]byte, ed25519.PrivateKey, error) {
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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

func GenerateIntermediateCA(issuer, subject string, notBefore, notAfter time.Time, parentCrt x509.Certificate, parentPrivKey ed25519.PrivateKey) ([]byte, ed25519.PrivateKey, error) {
	crt := &x509.Certificate{
		// TODO(corby): the combination of issuer + serial number must be unique.
		SerialNumber: big.NewInt(209),
		Subject: pkix.Name{
			Organization: []string{subject},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

func WriteCertificateFile(crt []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return WriteCertificate(crt, file)
}

func WriteCertificate(crt []byte, dst io.Writer) error {
	return pem.Encode(dst, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt,
	})
}

func WritePrivateKeyFile(key ed25519.PrivateKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return WritePrivateKey(key, file)
}

func WritePrivateKey(key ed25519.PrivateKey, dst io.Writer) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(dst, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

func ReadCertificateFile(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ReadCertificate(f)
}

func ReadCertificate(r io.Reader) (*x509.Certificate, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	p, _ := pem.Decode(buf.Bytes())

	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func ReadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKey(f)
}

func ReadPrivateKey(r io.Reader) (ed25519.PrivateKey, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	pKey, _ := pem.Decode(buf.Bytes())

	privkey, err := x509.ParsePKCS8PrivateKey(pKey.Bytes)
	if err != nil {
		return nil, err
	}

	return privkey.(ed25519.PrivateKey), nil
}
