package generic_test

import (
	"strings"
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestPKIX(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.Generate()
	t.Log("Public Key", asym.PublicKey)
	t.Log("Secret Key", asym.SecretKey)
	r.NoError(t, err)

	tests := []struct {
		name string
		pkix generic.PKIX
	}{
		{
			name: "Raw keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
			},
		},
		{
			name: "Raw keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
			},
		},
		{
			name: "Hex encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.Hex{},
			},
		},
		{
			name: "Hex encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.Hex{},
			},
		},
		{
			name: "Base64 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.Base64{},
			},
		},
		{
			name: "Base64 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.Base64{},
			},
		},
		{
			name: "UrlBase64 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.UrlBase64{},
			},
		},
		{
			name: "UrlBase64 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.UrlBase64{},
			},
		},
		{
			name: "RawUrlBase64 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.RawUrlBase64{},
			},
		},
		{
			name: "RawUrlBase64 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.RawUrlBase64{},
			},
		},
		{
			name: "RawBase64 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.RawBase64{},
			},
		},
		{
			name: "RawBase64 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.RawBase64{},
			},
		},
		{
			name: "Base32 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.Base32{},
			},
		},
		{
			name: "Base32 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.Base32{},
			},
		},
		{
			name: "PaddinglessBase32 encoded keys",
			pkix: generic.PKIX{
				ExportPublicKey: asym.SecretKey.Public(),
				Encoder:         &generic.PaddinglessBase32{},
			},
		},
		{
			name: "PaddinglessBase32 encoded keys with ed25519.PublicKey",
			pkix: generic.PKIX{
				ExportPublicKey: asym.PublicKey,
				Encoder:         &generic.PaddinglessBase32{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = tt.pkix.Export()
			r.NoError(t, err)
			t.Log("PKIX wrapped Ed25519 Public Key", tt.pkix.ExportData)

			pkix2 := generic.PKIX{
				ImportData: tt.pkix.ExportData,
				Encoder:    tt.pkix.Encoder,
			}

			err = pkix2.Import()
			r.NoError(t, err)
			r.Equal(t, asym.PublicKey, pkix2.PublicKey)
		})
	}
}

func TestFailPKIX(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.Generate()
	t.Log("Public Key", asym.PublicKey)
	t.Log("Secret Key", asym.SecretKey)
	r.NoError(t, err)

	tests := []struct {
		name          string
		pkix          generic.PKIX
		expectedError string
	}{
		{
			name:          "No keys export",
			pkix:          generic.PKIX{},
			expectedError: "missing public key",
		},
		{
			name: "Double key export",
			pkix: generic.PKIX{
				PublicKey:       asym.PublicKey,
				ExportPublicKey: asym.SecretKey.Public(),
			},
			expectedError: "cannot export both public key and export public key",
		},
		{
			name: "Wrong data import",
			pkix: generic.PKIX{
				ImportData: "wrong data",
			},
			expectedError: "invalid pem block",
		},
		{
			name: "Missing import data",
			pkix: generic.PKIX{
				ImportData: "",
			},
			expectedError: "import data is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if strings.Contains(test.name, "export") {
				err = test.pkix.Export()
				r.Error(t, err)
				r.EqualError(t, err, test.expectedError)
			}
			if strings.Contains(test.name, "import") {
				err = test.pkix.Import()
				r.Error(t, err)
				r.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestPKCS(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.Generate()
	t.Log("Public Key", asym.PublicKey)
	t.Log("Secret Key", asym.SecretKey)
	r.NoError(t, err)

	tests := []struct {
		name string
		pkcs generic.PKCS
	}{
		{
			name: "Raw keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
			},
		},
		{
			name: "Hex encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.Hex{},
			},
		},
		{
			name: "Base64 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.Base64{},
			},
		},
		{
			name: "UrlBase64 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.UrlBase64{},
			},
		},
		{
			name: "RawUrlBase64 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.RawUrlBase64{},
			},
		},
		{
			name: "RawBase64 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.RawBase64{},
			},
		},
		{
			name: "Base32 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.Base32{},
			},
		},
		{
			name: "PaddinglessBase32 encoded keys",
			pkcs: generic.PKCS{
				SecretKey: asym.SecretKey,
				Encoder:   &generic.PaddinglessBase32{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err = tt.pkcs.Export()
			r.NoError(t, err)
			t.Log("PKCS wrapped Ed25519 Secret Key", tt.pkcs.ExportData)

			pkcs2 := generic.PKCS{
				ImportData: tt.pkcs.ExportData,
				Encoder:    tt.pkcs.Encoder,
			}

			err = pkcs2.Import()
			r.NoError(t, err)
			r.Equal(t, asym.SecretKey, pkcs2.SecretKey)
		})
	}
}

func TestFailPKCS(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.Generate()
	t.Log("Public Key", asym.PublicKey)
	t.Log("Secret Key", asym.SecretKey)
	r.NoError(t, err)

	tests := []struct {
		name          string
		pkcs          generic.PKCS
		expectedError string
	}{
		{
			name:          "No keys export",
			pkcs:          generic.PKCS{},
			expectedError: "missing secret key",
		},
		{
			name:          "Missing import data",
			pkcs:          generic.PKCS{},
			expectedError: "import data is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if strings.Contains(test.name, "export") {
				err = test.pkcs.Export()
				r.Error(t, err)
				r.EqualError(t, err, test.expectedError)
			}
			if strings.Contains(test.name, "import") {
				err = test.pkcs.Import()
				r.Error(t, err)
				r.EqualError(t, err, test.expectedError)
			}
		})
	}
}
