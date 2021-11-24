package license

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	license := `
		{
			"id":"ae9a7251-3008-4ec5-99f1-00f91f04505e",
			"type":"non-commercial",
			"environment":"production",
			"created":"foobar",
			"signature": "s8ssMvNHiyD8HwMEOsGnFFJ48aleRVaeqUuqDY5N2RRuH16adxMBSx+iLxSuB0CBVQ1HcoW/I8pr7+ioC3H5AQ=="
		}
	`

	l, err := Verify(strings.NewReader(license), x509.Certificate{})
	if err != nil {
		t.Error(err)
	}
	t.Log(l)
}
