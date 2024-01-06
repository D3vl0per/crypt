package symmetric_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/insecure/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestSymmetricEncryption(t *testing.T) {
	testCases := []struct {
		name    string
		sym     symmetric.Symmetric
		key     []byte
		payload []byte
	}{
		{
			name:    "NaClSecretBox",
			sym:     &symmetric.SecretBox{},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "AesCTR",
			sym:     &symmetric.AesCTR{},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "AesCBC",
			sym:     &symmetric.AesCBC{},
			key:     generateKey(t, 32),
			payload: []byte("exampleplaintext"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := tc.sym.Encrypt(tc.key, tc.payload)
			r.NoError(t, err)

			plaintext, err := tc.sym.Decrypt(tc.key, ciphertext)
			r.NoError(t, err)

			r.Equal(t, tc.payload, plaintext)
		})
	}
}

func TestAesCBCKeyFault(t *testing.T) {
	testCases := []struct {
		key         []byte
		payload     []byte
		expectedErr string
		sym     symmetric.Symmetric
	}{	
		{
			key:         generateKey(t, 31),
			payload:     make([]byte, 16),
			expectedErr: "invalid key size",
			sym: &symmetric.SecretBox{},
		},
		{
			key:         generateKey(t, 31),
			payload:     make([]byte, 16),
			expectedErr: "invalid key size",
			sym: &symmetric.AesCTR{},
		},
		{
			key:         generateKey(t, 33),
			payload:     make([]byte, 16),
			expectedErr: "invalid key size",
			sym: &symmetric.AesCTR{},
		},
		{
			key:         make([]byte, 32),
			payload:     make([]byte, 16),
			expectedErr: "key is all zero",
			sym: &symmetric.AesCTR{},
		},
		{
			key:         generateKey(t, 31),
			payload:     make([]byte, 16),
			expectedErr: "invalid key size",
			sym: &symmetric.AesCBC{},
		},
		{
			key:         generateKey(t, 33),
			payload:     make([]byte, 16),
			expectedErr: "invalid key size",
			sym: &symmetric.AesCBC{},
		},
		{
			key:         make([]byte, 32),
			payload:     make([]byte, 16),
			expectedErr: "key is all zero",
			sym: &symmetric.AesCBC{},
		},
		{
			key:         generateKey(t, 32),
			payload:     make([]byte, 14),
			expectedErr: "payload is not a multiple of the block size",
			sym: &symmetric.AesCBC{},
		},
	}

	for _, tc := range testCases {
		ciphertext, err := tc.sym.Encrypt(tc.key, tc.payload)
		r.Nil(t, ciphertext)
		r.ErrorContains(t, err, tc.expectedErr)

		plaintext, err := tc.sym.Decrypt(tc.key, ciphertext)
		r.Nil(t, plaintext)
		r.ErrorContains(t, err, tc.expectedErr)
	}
}

func generateKey(t *testing.T, size int) []byte {
	key, err := generic.CSPRNG(int64(size))
	r.NoError(t, err)
	return key
}
