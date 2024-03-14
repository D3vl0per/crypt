package asymmetric_test

import (
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/hash"
	r "github.com/stretchr/testify/require"
)

func TestMinimalisticAttestation(t *testing.T) {
	ecdsa := asymmetric.Ed25519{}
	err := ecdsa.Generate()
	r.NoError(t, err)

	salt, err := generic.CSPRNG(32)
	r.NoError(t, err)

	tests := []struct {
		name       string
		attestator asymmetric.Minimalistic
		payload    []byte
	}{
		{
			name: "Minimalistic with known padding",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Hex{},
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload: []byte("Correct Horse Battery Staple"),
		},
		{
			name: "Base64 encoder with known separator",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Base64{},
				},
				Serialization: &asymmetric.KnownSeparator{
					Separator:         ".",
					PayloadPosition:   0,
					SignaturePosition: 1,
				},
				Encoder: &generic.Base64{},
			},
			payload: []byte("Correct Horse Battery Staple"),
		},
		{
			name: "Blake2b-512 with known padding",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Hex{},
				},
				Hasher: &hash.Blake2b512{},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload: []byte("Correct Horse Battery Staple"),
		},
		{
			name: "Blake2b-512-HMAC with known padding",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Hex{},
				},
				Hasher: &hash.Blake2b512{
					HmacSecret: salt,
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload: []byte("Correct Horse Battery Staple"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Log("Test: ", test.name)

			token, err := test.attestator.Sign(test.payload)
			r.NoError(t, err)
			t.Log("Token:", token)

			result, err := test.attestator.Verify(token)
			r.NoError(t, err)
			r.True(t, result)

			parsedToken, err := test.attestator.Parse(token)
			r.NoError(t, err)
			r.Equal(t, string(test.payload), parsedToken)
		})
	}
}

func TestFaultMinimalisticAttestation(t *testing.T) {
	ecdsa := asymmetric.Ed25519{}
	err := ecdsa.Generate()
	r.NoError(t, err)

	// salt, err := generic.CSPRNG(32)
	// r.NoError(t, err)

	tests := []struct {
		name                string
		attestator          asymmetric.Minimalistic
		payload             []byte
		expectedSignError   string
		expectedVerifyError string
		expectedParseError  string
		token               string
	}{
		{
			name: "Sign Missing Suite",
			attestator: asymmetric.Minimalistic{
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload:           []byte("Correct Horse Battery Staple"),
			expectedSignError: "missing signing suite declaration",
		},
		{
			name: "Sign Missing Secret Key",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload:           []byte("Correct Horse Battery Staple"),
			expectedSignError: "missing secret key declaration",
		},
		{
			name: "Sign Encoder mismatch",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload:           []byte("Correct Horse Battery Staple"),
			expectedSignError: "encoder mismatch between signing suite and attestation",
		},
		{
			name: "Sign Serializer error bigger padding than the data",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Hex{},
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 250,
				},
			},
			payload:           []byte("Correct Horse Battery Staple"),
			expectedSignError: "serializer error: invalid padding, bigger than the data",
		},
		{
			name: "Verify Missing public key",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					Encoder:   &generic.Hex{},
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload:             []byte("Correct Horse Battery Staple"),
			expectedVerifyError: "missing public key declaration",
		},
		{
			name: "Verify Encoder Missmatch",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Base64{},
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 128,
				},
			},
			payload:             []byte("Correct Horse Battery Staple"),
			expectedVerifyError: "encoder mismatch between signing suite and attestation",
		},
		{
			name: "Verify Serializer error zero padding",
			attestator: asymmetric.Minimalistic{
				Suite: &asymmetric.Ed25519{
					SecretKey: ecdsa.SecretKey,
					PublicKey: ecdsa.PublicKey,
					Encoder:   &generic.Hex{},
				},
				Serialization: &asymmetric.KnownPadding{
					Padding: 0,
				},
			},
			payload:             []byte("Correct Horse Battery Staple"),
			expectedVerifyError: "deserializer error: missing padding declaration",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Log("Test: ", test.name)

			if test.expectedSignError != "" {
				token, err := test.attestator.Sign(test.payload)
				t.Log("Token:", token)
				r.EqualError(t, err, test.expectedSignError)
				return
			}

			if test.expectedVerifyError != "" {
				result, err := test.attestator.Verify(test.token)
				r.False(t, result)
				r.EqualError(t, err, test.expectedVerifyError)
				return
			}

			if test.expectedParseError != "" {
				parsedToken, err := test.attestator.Parse(test.token)
				r.EqualError(t, err, test.expectedParseError)
				r.Equal(t, string(test.payload), parsedToken)
				return
			}
		})
	}
}
