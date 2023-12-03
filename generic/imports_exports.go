package generic

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type ImportExport interface {
	Import() error
	Export() error
}

// PKIX is a generic struct for import and export Ed25519 public key
// One way to import:
// 1. ImportData (string) -> PublicKey (ed25519.PublicKey)
// Two ways to export:
// 1. PublicKey (ed25519.PublicKey) -> ExportData (string)
// 2. ExportPublicKey (crypto.PublicKey) -> ExportData (string)
type PKIX struct {
	PublicKey       ed25519.PublicKey
	ImportData      string
	ExportData      string
	ExportPublicKey crypto.PublicKey
	Encoder         Encoder
}

type PKCS struct {
	SecretKey  ed25519.PrivateKey
	ImportData string
	ExportData string
	Encoder    Encoder
}

// struct PKIX ImportData (string) -> struct PKIX PublicKey (ed25519.PublicKey)
func (e *PKIX) Import() error {

	if e.ImportData == "" {
		return errors.New("import data is empty")
	}

	var err error
	var data []byte
	if e.Encoder == nil {
		data = []byte(e.ImportData)
	} else {
		data, err = e.Encoder.Decode(e.ImportData)
		if err != nil {
			return err
		}
	}

	pemBlock, rest := pem.Decode(data)
	if len(rest) != 0 {
		return errors.New("invalid pem block")
	}

	pkRaw, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return err
	}
	// nolint:errcheck
	pkC := pkRaw.(crypto.PublicKey)
	// nolint:errcheck
	e.PublicKey = pkC.(ed25519.PublicKey)
	return nil
}

// Two ways to export:
// 1. struct PKIX PublicKey (ed25519.PublicKey) -> struct PKIX ExportData (string)
// 2. struct PKIX ExportPublicKey (crypto.PublicKey) -> struct PKIX ExportData (string)
func (e *PKIX) Export() error {

	if e.ExportPublicKey == nil && e.PublicKey == nil {
		return errors.New("missing public key")
	}

	if e.ExportPublicKey != nil && e.PublicKey != nil {
		return errors.New("cannot export both public key and export public key")
	}

	var err error
	var marshal []byte
	if e.ExportPublicKey != nil {
		marshal, err = x509.MarshalPKIXPublicKey(e.ExportPublicKey)
		if err != nil {
			return err
		}
	} else {
		marshal, err = x509.MarshalPKIXPublicKey(e.PublicKey)
		if err != nil {
			return err
		}
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshal,
	}

	if e.Encoder == nil {
		e.ExportData = string(pem.EncodeToMemory(block))
	} else {
		e.ExportData = e.Encoder.Encode(pem.EncodeToMemory(block))
	}

	return nil
}

// struct PKCS ImportData (string) -> struct PKCS SecretKey (ed25519.PrivateKey)
func (e *PKCS) Import() error {

	if e.ImportData == "" {
		return errors.New("import data is empty")
	}

	var err error
	var data []byte
	if e.Encoder == nil {
		data = []byte(e.ImportData)
	} else {
		data, err = e.Encoder.Decode(e.ImportData)
		if err != nil {
			return err
		}
	}

	pemBlock, rest := pem.Decode(data)
	if len(rest) != 0 {
		return errors.New("invalid pem block")
	}

	pkRaw, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}
	// nolint:errcheck
	pkC := pkRaw.(crypto.PrivateKey)
	// nolint:errcheck
	e.SecretKey = pkC.(ed25519.PrivateKey)
	return nil
}

// struct PKCS SecretKey (ed25519.PrivateKey) -> struct PKCS ExportData (string)
func (e *PKCS) Export() error {

	if e.SecretKey == nil {
		return errors.New("missing secret key")
	}

	b, err := x509.MarshalPKCS8PrivateKey(e.SecretKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	if e.Encoder == nil {
		e.ExportData = string(pem.EncodeToMemory(block))
	} else {
		e.ExportData = e.Encoder.Encode(pem.EncodeToMemory(block))
	}

	return nil
}
