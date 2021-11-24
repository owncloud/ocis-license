package license

import (
	"encoding/hex"
	"testing"
)

func TestParseHeader(t *testing.T) {
	encoded := "" +
		"eyJ2ZXJzaW9uIjoiMSIsInNpZ25hdHVyZSI6Ik0wd3RsaXZzMjVwRjVmd0pI" +
		"YzF6UkZLZWlzOFlOT05xYklxTDhlMlJZNFRqZGFTMW03LzNXckUvOFpsc054" +
		"eEw5U2hWVURObmUzTmlOYk9zZjNYbUNnPT0iLCJjZXJ0aWZpY2F0ZSI6Ik1J" +
		"SUJJRENCMDZBREFnRUNBZ0VjTUFVR0F5dGxjREFZTVJZd0ZBWURWUVFERXcx" +
		"dmQyNURiRzkxWkNCSGJXSklNQjRYRFRJeE1URXlOREUwTXpnME4xb1hEVEl6" +
		"TVRFeU5ERTBNemcwTjFvd0dERVdNQlFHQTFVRUF4TU5iM2R1UTJ4dmRXUWdS" +
		"MjFpU0RBcU1BVUdBeXRsY0FNaEFKZlF0VXhCdWY4WllBZER1MlU5RldNVUFi" +
		"V205TUJEVWRJTlNaTnpWckpNbzBJd1FEQU9CZ05WSFE4QkFmOEVCQU1DQVlZ" +
		"d0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVAyamNLdUhO" +
		"a3pQK29Weml1ZmcyWWpXN0hmY3dCUVlESzJWd0EwRUFtemZ1OVNGeXpMNjBT" +
		"K3VRTlNXZXVTZXp2eVFFMzFnNUNDc2t1MmZCUkcyRHB3ZW90NFd0dEVhTGJ5" +
		"TVFtUEhldi81dlQ0MG03MUNXZlBOTjdYSzZDdz09In0="

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
