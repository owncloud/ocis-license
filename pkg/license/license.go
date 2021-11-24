// Package license provides functions to create, sign and verify ocis licenses.
package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	partsDelimiter = "."
)

func decodePart(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func encodePart(part []byte) []byte {
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	// We can safely ignore the errors here since we are using
	// bytes.Buffer as the writer and Write from bytes.Buffer doesn't
	// return an error.
	_, _ = encoder.Write(part)
	_ = encoder.Close()
	return buf.Bytes()
}

// parseHeader parses the header part of the license.
func parseHeader(s string) (Header, error) {
	decoded, err := decodePart(s)
	if err != nil {
		return Header{}, err
	}
	var h Header
	if err := json.Unmarshal(decoded, &h); err != nil {
		return Header{}, err
	}
	return h, nil
}

func parsePayload(s string) (Payload, error) {
	decoded, err := decodePart(s)
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// Verify reads the license and verifies the signature.
// If the signature is correct the license will be parsed and returned.
// If the signature is incorrect or the parsing fails, an error will be returned.
func Verify(r io.Reader, rootCert x509.Certificate) (License, error) {
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		return License{}, err
	}

	parts := strings.Split(buf.String(), partsDelimiter)
	if len(parts) != 2 {
		return License{}, errors.New("invalid license")
	}

	header, err := parseHeader(parts[0])
	if err != nil {
		return License{}, err
	}

	cert, err := x509.ParseCertificate(header.Certificate)
	if err != nil {
		return License{}, err
	}

	decodedPayload, err := decodePart(parts[1])
	if err != nil {
		return License{}, err
	}

	if err := cert.CheckSignature(x509.PureEd25519, decodedPayload, header.PayloadSignature); err != nil {
		return License{}, err
	}

	if err := cert.CheckSignatureFrom(&rootCert); err != nil {
		return License{}, err
	}

	payload, err := parsePayload(parts[1])
	if err != nil {
		return License{}, err
	}
	return License{Header: header, Payload: payload}, nil
}

// Header contains technical info about the license.
// The header is not signed and therefor the values should not be trusted blindly.
type Header struct {
	// Version represents the license version.
	// This field enables us to change license handling or format in the future.
	Version string `json:"version"`
	// The signature of the payload.
	PayloadSignature []byte `json:"payload_ signature"`
	// The certificate with which the signature was calculated.
	Certificate []byte `json:"certificate"`
}

// Payload contains the business information of the license.
// The payload gets signed and can be verified by checking the signature in the header
// using the certificate from the header.
// The values can be trusted when the signature was verified.
type Payload struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Environment string    `json:"environment"`
	Created     time.Time `json:"created"`
	Features    []string  `json:"features"`
	SLA         string    `json:"sla"`
}

func Sign(l *License, crt x509.Certificate, privateKey ed25519.PrivateKey) error {
	m, err := json.Marshal(l.Payload)
	if err != nil {
		return err
	}

	sig := ed25519.Sign(privateKey, m)
	if err := crt.CheckSignature(x509.PureEd25519, m, sig); err != nil {
		return err
	}

	l.Header.PayloadSignature = sig
	l.Header.Certificate = crt.Raw

	return nil
}

type License struct {
	Header  Header
	Payload Payload
}

func (l License) Encode(w io.Writer) error {
	m1, err := json.Marshal(l.Header)
	if err != nil {
		return err
	}

	m2, err := json.Marshal(l.Payload)
	if err != nil {
		return err
	}

	_, err = w.Write(encodePart(m1))
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, ".")
	if err != nil {
		return err
	}
	_, err = w.Write(encodePart(m2))
	if err != nil {
		return err
	}

	return nil
}

func (l License) EncodeToString() (string, error) {
	var sb strings.Builder
	err := l.Encode(&sb)
	return sb.String(), err
}
