package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func IsValidPemCertificate(content []byte) bool {
	_, err := ParsePemCertificate(content)
	return err == nil
}

func ParsePemCertificate(content []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(content)
	if pemBlock == nil {
		return nil, errors.New("invalid pem file")
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

func IsValidPem(content []byte) bool {
	pemBlock, _ := pem.Decode(content)
	if pemBlock == nil {
		return false
	}
	return true
}
