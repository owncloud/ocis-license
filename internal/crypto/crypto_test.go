package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestWriteCertificate(t *testing.T) {
	crt, _ := hex.DecodeString("" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323431323232" +
		"32345a170d3331313132343132323232345a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b657003210071533e84cc4d" +
		"57b99735781e9bca4efa243612cac311004d6783b870deeeba3ca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e04160414c694a1b1bacd64fbf98b6ec55d0e186d" +
		"4c492228300506032b6570034100cc373a27e243473f3f596b47f194721d" +
		"3a28ee5f27e8ee64bf32f5656214fff4e6099cb9a43806bc6d0c43c1bd4e" +
		"559537b9da2318e63207100c34ceb8f05008")

	expected := "" +
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIBHDCBz6ADAgECAgEBMAUGAytlcDAWMRQwEgYDVQQDEwt0ZXN0c3ViamVjdDAe\n" +
		"Fw0yMTExMjQxMjIyMjRaFw0zMTExMjQxMjIyMjRaMBYxFDASBgNVBAMTC3Rlc3Rz\n" +
		"dWJqZWN0MCowBQYDK2VwAyEAcVM+hMxNV7mXNXgem8pO+iQ2EsrDEQBNZ4O4cN7u\n" +
		"ujyjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n" +
		"BBTGlKGxus1k+/mLbsVdDhhtTEkiKDAFBgMrZXADQQDMNzon4kNHPz9Za0fxlHId\n" +
		"OijuXyfo7mS/MvVlYhT/9OYJnLmkOAa8bQxDwb1OVZU3udojGOYyBxAMNM648FAI\n" +
		"-----END CERTIFICATE-----\n"

	var sb strings.Builder
	_ = WriteCertificate(crt, &sb)

	if sb.String() != expected {
		t.Errorf("Result doesn't have the expected format:\n %s", sb.String())
	}
}

func TestReadCertificate(t *testing.T) {
	reader := strings.NewReader("" +
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIBHDCBz6ADAgECAgEBMAUGAytlcDAWMRQwEgYDVQQDEwt0ZXN0c3ViamVjdDAe\n" +
		"Fw0yMTExMjQxMjIyMjRaFw0zMTExMjQxMjIyMjRaMBYxFDASBgNVBAMTC3Rlc3Rz\n" +
		"dWJqZWN0MCowBQYDK2VwAyEAcVM+hMxNV7mXNXgem8pO+iQ2EsrDEQBNZ4O4cN7u\n" +
		"ujyjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n" +
		"BBTGlKGxus1k+/mLbsVdDhhtTEkiKDAFBgMrZXADQQDMNzon4kNHPz9Za0fxlHId\n" +
		"OijuXyfo7mS/MvVlYhT/9OYJnLmkOAa8bQxDwb1OVZU3udojGOYyBxAMNM648FAI\n" +
		"-----END CERTIFICATE-----\n")

	expected := "" +
		"3082011c3081cfa003020102020101300506032b65703016311430120603" +
		"550403130b746573747375626a656374301e170d32313131323431323232" +
		"32345a170d3331313132343132323232345a301631143012060355040313" +
		"0b746573747375626a656374302a300506032b657003210071533e84cc4d" +
		"57b99735781e9bca4efa243612cac311004d6783b870deeeba3ca3423040" +
		"300e0603551d0f0101ff040403020186300f0603551d130101ff04053003" +
		"0101ff301d0603551d0e04160414c694a1b1bacd64fbf98b6ec55d0e186d" +
		"4c492228300506032b6570034100cc373a27e243473f3f596b47f194721d" +
		"3a28ee5f27e8ee64bf32f5656214fff4e6099cb9a43806bc6d0c43c1bd4e" +
		"559537b9da2318e63207100c34ceb8f05008"

	crt, _ := ReadCertificate(reader)

	if hex.EncodeToString(crt.Raw) != expected {
		t.Error("ReadCertificate returned unexpected result")
	}
}

func TestReadCertificate_InvalidContent(t *testing.T) {
	inputs := []string{
		"not a certificate",
		"" +
			"-----BEGIN CERTIFICATE-----\n" +
			"MC4CAQAwBQYDK2VwBCIEIFlFTExPV19TVUJNQVJJTkVZRUxMT1dfU1VCTUFSSU5F\n" +
			"-----END CERTIFICATE-----\n",
	}
	for _, i := range inputs {
		reader := strings.NewReader(i)
		_, err := ReadCertificate(reader)

		if err == nil {
			t.Error("ReadCertificate should return error on invalid input")
		}
	}
}

func TestReadCertificateFile(t *testing.T) {
	privkey, err := ReadCertificateFile("../../testdata/test.crt")
	if err != nil {
		t.Error(err.Error())
	}
	if privkey == nil {
		t.Error("ReadCertificateFile failed")
	}
}

func TestReadCertificateFile_InvalidPath(t *testing.T) {
	_, err := ReadCertificateFile("../../testdata/nonexistent.file")
	if err == nil {
		t.Error("Expected ReadCertificateFile to return an error")
	}
}

func TestWritePrivateKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte("YELLOW_SUBMARINEYELLOW_SUBMARINE"))

	expected := "" +
		"-----BEGIN PRIVATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEIFlFTExPV19TVUJNQVJJTkVZRUxMT1dfU1VCTUFSSU5F\n" +
		"-----END PRIVATE KEY-----\n"

	var sb strings.Builder
	_ = WritePrivateKey(key, &sb)

	if sb.String() != expected {
		t.Errorf("Result doesn't have the expected format:\n %s", sb.String())
	}
}

func TestReadPrivateKey(t *testing.T) {
	reader := strings.NewReader("" +
		"-----BEGIN PRIVATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEIFlFTExPV19TVUJNQVJJTkVZRUxMT1dfU1VCTUFSSU5F\n" +
		"-----END PRIVATE KEY-----\n")

	key, _ := ReadPrivateKey(reader)

	if string(key.Seed()) != "YELLOW_SUBMARINEYELLOW_SUBMARINE" {
		t.Error("ReadPrivateKey returned unexpected result")
	}
}

func TestReadPrivateKey_InvalidInput(t *testing.T) {
	inputs := []string{
		"not a private key",
		"" +
			"-----BEGIN PRIVATE KEY-----\n" +
			"MIIBHDCBz6ADAgECAgEBMAUGAytlcDAWMRQwEgYDVQQDEwt0ZXN0c3ViamVjdDAe\n" +
			"Fw0yMTExMjQxMjIyMjRaFw0zMTExMjQxMjIyMjRaMBYxFDASBgNVBAMTC3Rlc3Rz\n" +
			"dWJqZWN0MCowBQYDK2VwAyEAcVM+hMxNV7mXNXgem8pO+iQ2EsrDEQBNZ4O4cN7u\n" +
			"ujyjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n" +
			"BBTGlKGxus1k+/mLbsVdDhhtTEkiKDAFBgMrZXADQQDMNzon4kNHPz9Za0fxlHId\n" +
			"OijuXyfo7mS/MvVlYhT/9OYJnLmkOAa8bQxDwb1OVZU3udojGOYyBxAMNM648FAI\n" +
			"-----END PRIVATE KEY-----\n",
	}
	for _, i := range inputs {
		reader := strings.NewReader(i)
		_, err := ReadPrivateKey(reader)

		if err == nil {
			t.Error("ReadPrivateKey should return error on invalid input")
		}
	}
}

func TestReadPrivateKeyFile(t *testing.T) {
	privkey, err := ReadPrivateKeyFile("../../testdata/priv.key")
	if err != nil {
		t.Error(err.Error())
	}
	if privkey == nil {
		t.Error("ReadPrivateKeyFile failed")
	}
}

func TestReadPrivateKeyFile_InvalidPath(t *testing.T) {
	_, err := ReadPrivateKeyFile("../../testdata/nonexistent.file")
	if err == nil {
		t.Error("Expected ReadPrivateKeyFile to return an error")
	}
}

func TestGenerateRootCA(t *testing.T) {
	crt, privkey, err := GenerateRootCA("Test subject")

	if crt == nil || privkey == nil || err != nil {
		t.Error("GenerateRootCA failed unexpectedly")
	}

	msg := []byte("sign me")
	sig := ed25519.Sign(privkey, msg)

	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		t.Errorf("GenerateRootCA returned invalid certificate %s", err.Error())
	}

	if err := cert.CheckSignature(x509.PureEd25519, msg, sig); err != nil {
		t.Errorf("Cert returned by GenerateRootCA could not verify signature form private key")
	}
}

func TestGenerateIntermediateCA(t *testing.T) {
	rootCrt, rootPrivkey, _ := GenerateRootCA("Test subject")
	rootCert, _ := x509.ParseCertificate(rootCrt)

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Second * 60)

	crt, privkey, err := GenerateIntermediateCA(*big.NewInt(2), "Test issuer", "Test subject", notBefore, notAfter, *rootCert, rootPrivkey)
	if crt == nil || privkey == nil || err != nil {
		t.Error("GenerateIntermediateCA failed unexpectedly")
	}

	msg := []byte("sign me")
	sig := ed25519.Sign(privkey, msg)

	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		t.Errorf("GenerateIntermediateCA returned invalid certificate %s", err.Error())
	}

	if err := cert.CheckSignature(x509.PureEd25519, msg, sig); err != nil {
		t.Errorf("Cert returned by GenerateIntermediateCA could not verify signature form private key")
	}
}
