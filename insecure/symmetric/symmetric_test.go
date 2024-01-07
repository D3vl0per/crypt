package symmetric_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/insecure/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
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

func TestE2EFault(t *testing.T) {

	type cases struct {
		name string
		key         []byte
		payload     []byte
		expectedErr string
	}

	type testStructue struct {
		name   string
		sym     symmetric.Symmetric
		encrypt []cases
		decrypt []cases
	}

	testCases := []testStructue{
		{
			name:  "NaClSecretBox",
			sym: &symmetric.SecretBox{},
			encrypt: []cases{
				{	
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
			},
			decrypt: []cases{
				{	
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"non-decryptable payload, decryption error",
					key:         make([]byte, 32),
					payload:     make([]byte, 32),
					expectedErr: "decryption error",
				},
				{
					name:        "invalid payload,payload is too short",
					key:         generateKey(t, 32),
					payload:     make([]byte, 16),
					expectedErr: "payload is too short",
				},
			},
		},
		{
			name:  "AES-CTR",
			sym: &symmetric.AesCTR{},
			encrypt: []cases{
				{	
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key is all zero",
					key:         make([]byte, 32),
					payload:     make([]byte, 16),
					expectedErr: "key is all zero",
				},
			},
			decrypt: []cases{
				{	
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key is all zero",
					key:         make([]byte, 32),
					payload:     make([]byte, 16),
					expectedErr: "key is all zero",
				},
				{
					name:        "invalid payload, payload is too short",
					key:         generateKey(t, 32),
					payload:     make([]byte, 15),
					expectedErr: "payload is too short",
				},
			},
		},
		{
			name:  "AES-CBC",
			sym: &symmetric.AesCBC{},
			encrypt: []cases{
				{
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 15, invalid key size",
					key:         generateKey(t, 15),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key is all zero",
					key:         make([]byte, 32),
					payload:     make([]byte, 16),
					expectedErr: "key is all zero",
				}, 
				{
					name: 	  	"payload is not a multiple of the block size",
					key:         generateKey(t, 32),
					payload:     make([]byte, 14),
					expectedErr: "payload is not a multiple of the block size",
				},
			},
			decrypt: []cases{
				{	
					name: 	  	"key size 31, invalid key size",
					key:         generateKey(t, 31),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key size 15, invalid key size",
					key:         generateKey(t, 15),
					payload:     make([]byte, 16),
					expectedErr: "invalid key size",
				},
				{
					name: 	  	"key is all zero",
					key:         make([]byte, 32),
					payload:     make([]byte, 16),
					expectedErr: "key is all zero",
				}, 
				{
					name: 	  	"payload is not a multiple of the block size",
					key:         generateKey(t, 32),
					payload:     make([]byte, 14),
					expectedErr: "payload is not a multiple of the block size",
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, c := range tc.encrypt {
			t.Run(tc.name+ "/encryption/" + c.name, func(t *testing.T) {
				ciphertext, err := tc.sym.Encrypt(c.key, c.payload)
				r.Nil(t, ciphertext)
				r.ErrorContains(t, err, c.expectedErr)
			})
		}
		for _, c := range tc.decrypt {
			t.Run(tc.name+ "/decryption/" + c.name, func(t *testing.T) {
				plaintext, err := tc.sym.Decrypt(c.key, c.payload)
				r.Nil(t, plaintext)
				r.ErrorContains(t, err, c.expectedErr)
			})
		}
	}
}

func generateKey(t *testing.T, size int) []byte {
	key, err := generic.CSPRNG(int64(size))
	r.NoError(t, err)
	return key
}
