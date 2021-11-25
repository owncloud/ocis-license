package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owncloud/ocis-license/internal/crypto"
)

func TestParseHeader(t *testing.T) {
	encoded := "" +
		"eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoiTTB3dGxpdnMy" +
		"NXBGNWZ3SkhjMXpSRktlaXM4WU5PTnFiSXFMOGUyUlk0VGpkYVMxbTcvM1dy" +
		"RS84WmxzTnh4TDlTaFZVRE5uZTNOaU5iT3NmM1htQ2c9PSIsImNlcnRpZmlj" +
		"YXRlIjoiTUlJQklEQ0IwNkFEQWdFQ0FnRWNNQVVHQXl0bGNEQVlNUll3RkFZ" +
		"RFZRUURFdzF2ZDI1RGJHOTFaQ0JIYldKSU1CNFhEVEl4TVRFeU5ERTBNemcw" +
		"TjFvWERUSXpNVEV5TkRFME16ZzBOMW93R0RFV01CUUdBMVVFQXhNTmIzZHVR" +
		"Mnh2ZFdRZ1IyMWlTREFxTUFVR0F5dGxjQU1oQUpmUXRVeEJ1ZjhaWUFkRHUy" +
		"VTlGV01VQWJXbTlNQkRVZElOU1pOelZySk1vMEl3UURBT0JnTlZIUThCQWY4" +
		"RUJBTUNBWVl3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFkQmdOVkhRNEVGZ1FV" +
		"UDJqY0t1SE5relArb1Z6aXVmZzJZalc3SGZjd0JRWURLMlZ3QTBFQW16ZnU5" +
		"U0Z5ekw2MFMrdVFOU1dldVNlenZ5UUUzMWc1Q0Nza3UyZkJSRzJEcHdlb3Q0" +
		"V3R0RWFMYnlNUW1QSGV2LzV2VDQwbTcxQ1dmUE5ON1hLNkN3PT0ifQ=="

	expectedSignature := "" +
		"334c2d962becdb9a45e5fc091dcd7344529e8acf1834e36a6c8a8bf1ed91" +
		"6384e375a4b59bbff75ab13ff1996c371c4bf528555033677b736235b3ac" +
		"7f75e60a"

	expectedCert := "" +
		"308201203081d3a00302010202011c300506032b65703018311630140603" +
		"550403130d6f776e436c6f756420476d6248301e170d3231313132343134" +
		"333834375a170d3233313132343134333834375a30183116301406035504" +
		"03130d6f776e436c6f756420476d6248302a300506032b657003210097d0" +
		"b54c41b9ff19600743bb653d15631401b5a6f4c04351d20d49937356b24c" +
		"a3423040300e0603551d0f0101ff040403020186300f0603551d130101ff" +
		"040530030101ff301d0603551d0e041604143f68dc2ae1cd9333fea15ce2" +
		"b9f8366235bb1df7300506032b65700341009b37eef52172ccbeb44beb90" +
		"35259eb927b3bf2404df5839082b24bb67c1446d83a707a8b785adb4468b" +
		"6f231098f1debffe6f4f8d26ef50967cf34ded72ba0b"

	h, err := parseHeader(encoded)

	if err != nil {
		t.Error("parseHeader failed")
	}

	if h.Version != "1" || hex.EncodeToString(h.PayloadSignature) != expectedSignature || hex.EncodeToString(h.Certificate) != expectedCert {
		t.Errorf("parseHeader returned unexpected values in header: %v", h)
	}
}

func TestParseHeader_InvalidInputs(t *testing.T) {
	inputs := []string{
		"bm90IGpzb24=", // "not json" base64 encoded
		"not base64 encoded",
	}

	for _, i := range inputs {
		_, err := parseHeader(i)
		if err == nil {
			t.Errorf("Expected parseHeader to return an error with input: %s", i)
		}

	}
}

func TestParsePayload(t *testing.T) {
	encoded := "" +
		"eyJpZCI6ImE0MzQ1ZDFhLTRkM2YtMTFlYy1iNTI3LWU4NmE2NGEzNzc3NCIs" +
		"InR5cGUiOiJub24tY29tbWVyY2lhbCIsImVudmlyb25tZW50IjoiZGV2ZWxv" +
		"cG1lbnQiLCJjcmVhdGVkIjoiMjAyMS0xMS0yNFQxNzowMDoyNy40ODE3OTk4" +
		"ODgrMDE6MDAiLCJmZWF0dXJlcyI6WyJjb3JlIiwidGh1bWJuYWlscyIsInJl" +
		"cG9ydHMiXSwic2xhIjoiIn0="

	p, err := parsePayload(encoded)
	if err != nil {
		t.Error("parsePayload failed")
	}

	if p.ID != "a4345d1a-4d3f-11ec-b527-e86a64a37774" || p.Type != "non-commercial" || p.Environment != "development" || len(p.Features) != 3 {
		t.Errorf("parsePayload returned unexpected values in payload: %v", p)
	}
}

func TestParsePayload_InvalidInputs(t *testing.T) {
	inputs := []string{
		"bm90IGpzb24=", // "not json" base64 encoded
		"not base64 encoded",
	}

	for _, i := range inputs {
		_, err := parsePayload(i)
		if err == nil {
			t.Errorf("Expected parsePayload to return an error with input: %s", i)
		}

	}
}

func TestEncodePart(t *testing.T) {
	expected := "aGVsbG8gd29ybGQ="

	encoded := encodePart([]byte("hello world"))

	if string(encoded) != expected {
		t.Errorf("encodePart returned unexpected value: expected %s got %s", expected, encoded)
	}
}

func TestLicenseEncode_WihtoutSignature(t *testing.T) {
	license := New(Header{}, Payload{})

	var sb strings.Builder
	if err := license.Encode(&sb); !errors.Is(err, ErrNotSigned) {
		t.Error("Expected Encode to return ErrNotSigned error")
	}

	if _, err := license.EncodeToString(); !errors.Is(err, ErrNotSigned) {
		t.Error("Expected EncodeToString to return ErrNotSigned error")
	}
}

func TestEncode(t *testing.T) {
	crtBytes, _ := hex.DecodeString("" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323531313335" +
		"33375a170d3331313132353131333533375a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b6570032100180ffb1d22f3" +
		"f2b09589437650baa857d18ae56bf9969fc6322f9943801a41cca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e0416041439653fb3bdae4b0ebeca6bd830e0366b" +
		"668b61cf300506032b6570034100d5083525f9f86af69f238d9b79d38586" +
		"44582dc593b2dea6093f20e2e6713930595667101470144ebead89c13211" +
		"9f84ecfe96715608de2d9212330376c1f20f")
	crt, _ := x509.ParseCertificate(crtBytes)

	pkBytes, _ := hex.DecodeString("" +
		"302e020100300506032b657004220420fc7c154f9f8384186c8aacea18b4" +
		"7cb3da49c7e991ea09fb579cfdc0739b1849")
	privkey, _ := x509.ParsePKCS8PrivateKey(pkBytes)

	expectedLicense := "" +
		"eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoia09aaUVvcE92" +
		"SzFHSmhBR3B3cUtmTU5EOTVsWXAyam40V1IxK2lzRC9uNEpKZGsrNjAxQ1JV" +
		"WW9jVGFZK3JnRTFVd1lBMWxLM3U2ZnpBc0dlUFR1RFE9PSIsImNlcnRpZmlj" +
		"YXRlIjoiTUlJQkhEQ0J6NkFEQWdFQ0FnRUJNQVVHQXl0bGNEQVdNUlF3RWdZ" +
		"RFZRUURFd3QwWlhOMGMzVmlhbVZqZERBZUZ3MHlNVEV4TWpVeE1UTTFNemRh" +
		"Rncwek1URXhNalV4TVRNMU16ZGFNQll4RkRBU0JnTlZCQU1UQzNSbGMzUnpk" +
		"V0pxWldOME1Db3dCUVlESzJWd0F5RUFHQS83SFNMejhyQ1ZpVU4yVUxxb1Y5" +
		"R0s1V3Y1bHAvR01pK1pRNEFhUWN5alFqQkFNQTRHQTFVZER3RUIvd1FFQXdJ" +
		"QmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUTVaVCt6" +
		"dmE1TERyN0thOWd3NERaclpvdGh6ekFGQmdNclpYQURRUURWQ0RVbCtmaHE5" +
		"cDhqalp0NTA0V0dSRmd0eFpPeTNxWUpQeURpNW5FNU1GbFdaeEFVY0JST3Zx" +
		"Mkp3VElSbjRUcy9wWnhWZ2plTFpJU013TjJ3ZklQIn0=.eyJpZCI6ImY2MmZ" +
		"mZDBjLTYwNGMtNDI2Yi05NjZmLTE2NTMzYjYyOTJmMCIsInR5cGUiOiIiLCJ" +
		"lbnZpcm9ubWVudCI6IiIsImNyZWF0ZWQiOiIyMDIxLTExLTI1VDEzOjEyOjE" +
		"1KzAxOjAwIiwiZmVhdHVyZXMiOm51bGwsInNsYSI6IiJ9"

	created := time.Unix(1637842335, 0)
	license := New(Header{Version: "1"}, Payload{ID: "f62ffd0c-604c-426b-966f-16533b6292f0", Created: created})

	_ = Sign(&license, *crt, privkey.(ed25519.PrivateKey))

	var sb strings.Builder
	err := license.Encode(&sb)
	if err != nil {
		t.Errorf("Encode failed: %s", err.Error())
	}

	if sb.String() != expectedLicense {
		t.Errorf("Encoded license is not expected value. Expected %s Got %s", expectedLicense, sb.String())
	}

	if encoded, err := license.EncodeToString(); err != nil {
		t.Errorf("EncodeToString failed: %s", err.Error())
	} else if encoded != expectedLicense {
		t.Errorf("EncodeToString did not return expected value. Expected %s Got %s", expectedLicense, encoded)
	}
}

func TestEncode_WithNilWriter(t *testing.T) {
	license := New(Header{}, Payload{})
	if err := license.Encode(nil); err == nil {
		t.Error("Expected Encode with nil writer to return an error.")
	}
}

func TestSign(t *testing.T) {
	crtBytes, _ := hex.DecodeString("" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323531313335" +
		"33375a170d3331313132353131333533375a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b6570032100180ffb1d22f3" +
		"f2b09589437650baa857d18ae56bf9969fc6322f9943801a41cca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e0416041439653fb3bdae4b0ebeca6bd830e0366b" +
		"668b61cf300506032b6570034100d5083525f9f86af69f238d9b79d38586" +
		"44582dc593b2dea6093f20e2e6713930595667101470144ebead89c13211" +
		"9f84ecfe96715608de2d9212330376c1f20f")
	crt, _ := x509.ParseCertificate(crtBytes)

	pkBytes, _ := hex.DecodeString("" +
		"302e020100300506032b657004220420fc7c154f9f8384186c8aacea18b4" +
		"7cb3da49c7e991ea09fb579cfdc0739b1849")
	privkey, _ := x509.ParsePKCS8PrivateKey(pkBytes)

	license := New(Header{Version: "1"}, Payload{ID: uuid.NewString(), Created: time.Now()})

	err := Sign(&license, *crt, privkey.(ed25519.PrivateKey))
	if err != nil {
		t.Errorf("Sign failed: %s", err.Error())
	}

	if license.Header.PayloadSignature == nil {
		t.Error("Sign didn't set the signature")
	}

	if license.Header.Certificate == nil {
		t.Error("Sign didn't set the certificate")
	}

	m, _ := json.Marshal(license.Payload)
	if err := crt.CheckSignature(x509.PureEd25519, m, license.Header.PayloadSignature); err != nil {
		t.Error("Signature from Sign could not be verified")
	}
}

func TestSign_WithWrongCert(t *testing.T) {
	crtBytes, _ := hex.DecodeString("" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323531313335" +
		"33375a170d3331313132353131333533375a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b6570032100180ffb1d22f3" +
		"f2b09589437650baa857d18ae56bf9969fc6322f9943801a41cca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e0416041439653fb3bdae4b0ebeca6bd830e0366b" +
		"668b61cf300506032b6570034100d5083525f9f86af69f238d9b79d38586" +
		"44582dc593b2dea6093f20e2e6713930595667101470144ebead89c13211" +
		"9f84ecfe96715608de2d9212330376c1f20f")
	crt, _ := x509.ParseCertificate(crtBytes)

	privkey := ed25519.NewKeyFromSeed([]byte("YELLOW_SUBMARINEYELLOW_SUBMARINE"))

	license := New(Header{Version: "1"}, Payload{ID: uuid.NewString(), Created: time.Now()})

	err := Sign(&license, *crt, privkey)
	if err == nil {
		t.Errorf("Sign should fail if the cert doesn't belong to the private key")
	}

	if license.Header.PayloadSignature != nil || license.Header.Certificate != nil {
		t.Error("Sign failed but set a signature or certificate")
	}
}

func TestVerify(t *testing.T) {
	rootCrt, rootPrivkey, _ := crypto.GenerateRootCA("testsubject")
	rootCert, _ := x509.ParseCertificate(rootCrt)

	icrt, iprivkey, _ := crypto.GenerateIntermediateCA(*big.NewInt(2), "testissuer", "testsubject", time.Now(), time.Now().Add(time.Hour*1), *rootCert, rootPrivkey)
	icert, _ := x509.ParseCertificate(icrt)

	license := New(Header{Version: "1"}, Payload{ID: uuid.NewString(), Created: time.Now()})

	_ = Sign(&license, *icert, iprivkey)

	encoded, _ := license.EncodeToString()

	_, err := Verify(strings.NewReader(encoded), *rootCert)
	if err != nil {
		t.Errorf("Verify failed: %s", err.Error())
	}
}

func TestVerify_WithIncorrectParentCert(t *testing.T) {
	rootCrt, _, _ := crypto.GenerateRootCA("testsubject")
	rootCert, _ := x509.ParseCertificate(rootCrt)

	rootCrt2, rootPrivkey2, _ := crypto.GenerateRootCA("testsubject2")
	rootCert2, _ := x509.ParseCertificate(rootCrt2)

	license := New(Header{Version: "1"}, Payload{ID: uuid.NewString(), Created: time.Now()})

	_ = Sign(&license, *rootCert2, rootPrivkey2)

	encoded, _ := license.EncodeToString()

	_, err := Verify(strings.NewReader(encoded), *rootCert)
	if err == nil {
		t.Error("Verify should fail with wrong parent cert")
	}
}

func TestVerify_WithInvalidInputs(t *testing.T) {
	crtBytes, _ := hex.DecodeString("" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323531313335" +
		"33375a170d3331313132353131333533375a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b6570032100180ffb1d22f3" +
		"f2b09589437650baa857d18ae56bf9969fc6322f9943801a41cca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e0416041439653fb3bdae4b0ebeca6bd830e0366b" +
		"668b61cf300506032b6570034100d5083525f9f86af69f238d9b79d38586" +
		"44582dc593b2dea6093f20e2e6713930595667101470144ebead89c13211" +
		"9f84ecfe96715608de2d9212330376c1f20f")
	cert, _ := x509.ParseCertificate(crtBytes)

	inputs := []string{
		"some string",
		"some.string",
		"some.ohter.string.",
		"" +
			"eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoia09aaUVvcE92" +
			"SzFHSmhBR3B3cUtmTU5EOTVsWXAyam40V1IxK2lzRC9uNEpKZGsrNjAxQ1JV" +
			"WW9jVGFZK3JnRTFVd1lBMWxLM3U2ZnpBc0dlUFR1RFE9PSIsImNlcnRpZmlj" +
			"YXRlIjoiUE9pSXBvS1owWjdFcjEwOEpEOWxIUT09In0=.foo",
		"" +
			"eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoia09aaUVvcE92" +
			"SzFHSmhBR3B3cUtmTU5EOTVsWXAyam40V1IxK2lzRC9uNEpKZGsrNjAxQ1JV" +
			"WW9jVGFZK3JnRTFVd1lBMWxLM3U2ZnpBc0dlUFR1RFE9PSIsImNlcnRpZmlj" +
			"YXRlIjoiTUlJQkhEQ0J6NkFEQWdFQ0FnRUJNQVVHQXl0bGNEQVdNUlF3RWdZ" +
			"RFZRUURFd3QwWlhOMGMzVmlhbVZqZERBZUZ3MHlNVEV4TWpVeE1UTTFNemRh" +
			"Rncwek1URXhNalV4TVRNMU16ZGFNQll4RkRBU0JnTlZCQU1UQzNSbGMzUnpk" +
			"V0pxWldOME1Db3dCUVlESzJWd0F5RUFHQS83SFNMejhyQ1ZpVU4yVUxxb1Y5" +
			"R0s1V3Y1bHAvR01pK1pRNEFhUWN5alFqQkFNQTRHQTFVZER3RUIvd1FFQXdJ" +
			"QmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUTVaVCt6" +
			"dmE1TERyN0thOWd3NERaclpvdGh6ekFGQmdNclpYQURRUURWQ0RVbCtmaHE5" +
			"cDhqalp0NTA0V0dSRmd0eFpPeTNxWUpQeURpNW5FNU1GbFdaeEFVY0JST3Zx" +
			"Mkp3VElSbjRUcy9wWnhWZ2plTFpJU013TjJ3ZklQIn0=.invalidpayload",
		"" +
			"eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoia09aaUVvcE92" +
			"SzFHSmhBR3B3cUtmTU5EOTVsWXAyam40V1IxK2lzRC9uNEpKZGsrNjAxQ1JV" +
			"WW9jVGFZK3JnRTFVd1lBMWxLM3U2ZnpBc0dlUFR1RFE9PSIsImNlcnRpZmlj" +
			"YXRlIjoiTUlJQkhEQ0J6NkFEQWdFQ0FnRUJNQVVHQXl0bGNEQVdNUlF3RWdZ" +
			"RFZRUURFd3QwWlhOMGMzVmlhbVZqZERBZUZ3MHlNVEV4TWpVeE1UTTFNemRh" +
			"Rncwek1URXhNalV4TVRNMU16ZGFNQll4RkRBU0JnTlZCQU1UQzNSbGMzUnpk" +
			"V0pxWldOME1Db3dCUVlESzJWd0F5RUFHQS83SFNMejhyQ1ZpVU4yVUxxb1Y5" +
			"R0s1V3Y1bHAvR01pK1pRNEFhUWN5alFqQkFNQTRHQTFVZER3RUIvd1FFQXdJ" +
			"QmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUTVaVCt6" +
			"dmE1TERyN0thOWd3NERaclpvdGh6ekFGQmdNclpYQURRUURWQ0RVbCtmaHE5" +
			"cDhqalp0NTA0V0dSRmd0eFpPeTNxWUpQeURpNW5FNU1GbFdaeEFVY0JST3Zx" +
			"Mkp3VElSbjRUcy9wWnhWZ2plTFpJU013TjJ3ZklQIn0=.eyJpZCI6InNvbWV" +
			"0aGluZyIsInR5cGUiOiIiLCJlbnZpcm9ubWVudCI6IiIsImNyZWF0ZWQiOiI" +
			"yMDIxLTExLTI1VDEzOjEyOjE1KzAxOjAwIiwiZmVhdHVyZXMiOm51bGwsInN" +
			"sYSI6IiJ9",
	}

	for _, i := range inputs {
		_, err := Verify(strings.NewReader(i), *cert)
		if err == nil {
			t.Errorf("Expected Verify to fail with input %s", i)
		}
	}
}

func TestVerify_WithNilReader(t *testing.T) {
	crt, _, _ := crypto.GenerateRootCA("testsubject")
	cert, _ := x509.ParseCertificate(crt)

	if _, err := Verify(nil, *cert); err == nil {
		t.Error("Expected Verify with a nil reader to return an error.")
	}
}
