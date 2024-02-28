package tlscerts

import (
	"os"
	"testing"
)

func TestGenerateBaseSelfSignedCertKey(t *testing.T) {
	config := NewBaseCertificateConfig("myserver",
		"10.0.0.1,127.0.0.1",
		"myserver.mydomain.com, myserver.localhost")

	cert, key, err := GenerateSelfSignedCertKey(config, nil, nil)
	if err != nil {
		t.Error("Error generating certificate and key")
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}

	if key == nil {
		t.Error("Key is nil")
	}
}

func TestGenerateSelfSignedCertKey(t *testing.T) {
	config := NewCertificateConfig("US", "VA", "SomeCity",
		"MyCompany", "MyDivision",
		"myserver", "10.0.0.1,127.0.0.1",
		"myserver.mydomain.com, myserver.localhost")

	cert, key, err := GenerateSelfSignedCertKey(config, nil, nil)
	if err != nil {
		t.Error("Error generating certificate and key")
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}

	if key == nil {
		t.Error("Key is nil")
	}
}

func TestGenerateSelfSignedCertKeyWithTime(t *testing.T) {
	config := NewCertificateConfig("US", "VA", "SomeCity",
		"MyCompany", "MyDivision",
		"myserver", "192.168.0.1,127.0.0.1",
		"myserver.mydomain.com, myserver.localhost")

	cert, key, err := GenerateSelfSignedCertKey(config, nil, nil)
	if err != nil {
		t.Error("Error generating certificate and key")
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}

	if key == nil {
		t.Error("Key is nil")
	}
}

// This is the way the library is supposed to be used the most:
func TestGenerateSSCertificate(t *testing.T) {
	// Generate a Self Signed Certificate and Key
	// using the default parameters for the entity
	// and store them in the current directory.
	GenerateBaseSSCertKey("./",
		"myserver", "192.168.0.1,127.0.0.1",
		"myserver.mydomain.com, myserver.localhost")

	// Check if certificate file was generated
	_, err := os.Stat("cert.pem")
	if err != nil {
		t.Error("Certificate file was not generated")
	}

	// Check if key file was generated
	_, err = os.Stat("key.pem")
	if err != nil {
		t.Error("Key file was not generated")
	}
}
