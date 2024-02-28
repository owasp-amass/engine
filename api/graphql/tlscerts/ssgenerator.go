package tlscerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertificateConfig holds the user-specified values for the certificate.
type CertificateConfig struct {
	Country            []string
	State              []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
	CommonName         string
	ServerIP           []string
	ServerFQDN         []string
}

// NewBaseCertificateConfig creates a new CertificateConfig
// with default values for the entity and the provided parameters
// for the FQDN, IP and Common Server Name.
func NewBaseCertificateConfig(commonName, serverIP, serverFQDN string) CertificateConfig {
	return CertificateConfig{
		Country:            []string{"US"},
		State:              []string{"VA"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"MyCompany"},
		OrganizationalUnit: []string{"MyDivision"},
		CommonName:         commonName,
		ServerIP:           strings.Split(serverIP, ","),
		ServerFQDN:         strings.Split(serverFQDN, ","),
	}
}

// NewCertificateConfig creates a new CertificateConfig
// with the provided parameters.
func NewCertificateConfig(country, state, locality, organization, organizationalUnit, commonName, serverIP, serverFQDN string) CertificateConfig {
	return CertificateConfig{
		Country:            strings.Split(country, ","),
		State:              strings.Split(state, ","),
		Locality:           strings.Split(locality, ","),
		Organization:       strings.Split(organization, ","),
		OrganizationalUnit: strings.Split(organizationalUnit, ","),
		CommonName:         commonName,
		ServerIP:           strings.Split(serverIP, ","),
		ServerFQDN:         strings.Split(serverFQDN, ","),
	}
}

// This function generates a Self Signed Certificate using the
// default parameters for the entity and the provided parameters
// for the FQDN, IP and Common Server Name.
func GenerateBaseSSCertKey(path, commonName, serverIP,
	serverFQDN string) {
	config := NewBaseCertificateConfig(commonName, serverIP, serverFQDN)

	cert, key, err := GenerateSelfSignedCertKey(config, nil, nil)
	if err != nil {
		panic(err)
	}

	// Write the key and the certificate to files
	WritePEMToFile(path+"cert.pem", "CERTIFICATE", cert)
	WritePEMToFile(path+"key.pem", "EC PRIVATE KEY", key)
}

// GenerateSelfSignedCertKey generates a self-signed certificate and private key based on the given configuration.
func GenerateSelfSignedCertKey(config CertificateConfig, notBefore, notAfter *time.Time) ([]byte, []byte, error) {
	// Generate an ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Set up a certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            config.Country,
			Province:           config.State,
			Locality:           config.Locality,
			Organization:       config.Organization,
			OrganizationalUnit: config.OrganizationalUnit,
			CommonName:         config.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Set the NotBefore and NotAfter if provided
	if notBefore != nil {
		template.NotBefore = *notBefore
	}
	if notAfter != nil {
		template.NotAfter = *notAfter
	}

	// Add DNS names from ServerFQDN slice
	for _, fqdn := range config.ServerFQDN {
		template.DNSNames = append(template.DNSNames, fqdn)
	}
	// Add the common name with .localhost suffix
	template.DNSNames = append(template.DNSNames, config.CommonName+".localhost")

	// Add IP addresses from ServerIP slice
	for _, ipStr := range config.ServerIP {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key and certificate to PEM format
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), nil
}

// WritePEMToFile writes data to a PEM file.
func WritePEMToFile(filename, pemType string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}
	pem.Encode(file, pemBlock)
}
