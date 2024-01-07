package symmetric_test

import (
	"bytes"
	"crypto/sha256"

	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestE2EE(t *testing.T) {
	testCases := []struct {
		name    string
		sym     symmetric.Symmetric
		key     []byte
		payload []byte
	}{
		{
			name:    "XOR",
			sym:     &symmetric.Xor{},
			key:     generateKey(t, 21),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "XChaCha20",
			sym:     &symmetric.XChaCha20{},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name: "XChaCha20-AAD",
			sym: &symmetric.XChaCha20{
				AdditionalData: []byte("AAD"),
			},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "AES-GCM-128",
			sym:     &symmetric.AesGCM{},
			key:     generateKey(t, 16),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name: "AES-GCM-128-AAD",
			sym: &symmetric.AesGCM{
				AdditionalData: []byte("AAD"),
			},
			key:     generateKey(t, 16),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "AES-GCM-192",
			sym:     &symmetric.AesGCM{},
			key:     generateKey(t, 24),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name: "AES-GCM-192-AAD",
			sym: &symmetric.AesGCM{
				AdditionalData: []byte("AAD"),
			},
			key:     generateKey(t, 24),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name:    "AES-GCM-256",
			sym:     &symmetric.AesGCM{},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
		{
			name: "AES-GCM-256",
			sym: &symmetric.AesGCM{
				AdditionalData: []byte("AAD"),
			},
			key:     generateKey(t, 32),
			payload: []byte("https://xkcd.com/936/"),
		},
	}
	hex := generic.Hex{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Key: %s", hex.Encode(tc.key))
			ciphertext, err := tc.sym.Encrypt(tc.key, tc.payload)
			r.NoError(t, err)

			t.Logf("Encrypted file size: %d\n", len(ciphertext))
			t.Logf("Encrypted value: %s", hex.Encode(ciphertext))

			plaintext, err := tc.sym.Decrypt(tc.key, ciphertext)
			r.NoError(t, err)

			t.Logf("Decrypted file size: %d\n", len(plaintext))
			t.Logf("Decrypted value: %s", string(plaintext))

			r.Equal(t, tc.payload, plaintext)
		})
	}

	testCasesStream := []struct {
		name    string
		sym     symmetric.SymmetricStream
		payload []byte
	}{
		{
			name: "XChaCha20-Stream",
			sym: &symmetric.XChaCha20Stream{
				Key: generateKey(t, 32),
			},
			payload: generateKey(t, 32),
		},
		{
			name: "XChaCha20-Stream",
			sym: &symmetric.XChaCha20Stream{
				Key:  generateKey(t, 32),
				Hash: sha256.New,
			},
			payload: generateKey(t, 32),
		},
	}

	for _, tc := range testCasesStream {
		t.Run(tc.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			in := bytes.NewReader(tc.payload)

			err := tc.sym.Encrypt(in, out)
			r.NoError(t, err)

			rr := bytes.NewReader(out.Bytes())
			out2 := &bytes.Buffer{}

			r.NoError(t, tc.sym.Decrypt(rr, out2))

			r.Equal(t, out2.Bytes(), tc.payload)
		})
	}

}

func TestE2EEFault(t *testing.T) {
	type cases struct {
		name        string
		key         []byte
		payload     []byte
		expectedErr string
	}

	type testStructue struct {
		name    string
		sym     symmetric.Symmetric
		encrypt []cases
		decrypt []cases
	}

	type casesStream struct {
		sym         symmetric.SymmetricStream
		name        string
		payload     []byte
		expectedErr string
	}

	type testStructueStream struct {
		name    string
		encrypt []casesStream
		decrypt []casesStream
	}

	testCases := []testStructue{
		{
			name: "XOR",
			sym:  &symmetric.Xor{},
			encrypt: []cases{
				{
					name:        "key and payload size mismatch",
					key:         make([]byte, 32),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "insecure xor operation, key and payload length need to be equal",
				},
				{
					name:        "zero ciphertext",
					key:         make([]byte, 32),
					payload:     make([]byte, 32),
					expectedErr: "xored array has just zeroes",
				},
			},
		},
		{
			name: "AES-GCM",
			sym:  &symmetric.AesGCM{},
			encrypt: []cases{
				{
					name:        "zero key",
					key:         make([]byte, 32),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name:        "key size 15, invalid key size",
					key:         generateKey(t, 15),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
				{
					name:        "key size 23, invalid key size",
					key:         generateKey(t, 23),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
				{
					name:        "key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
			},
			decrypt: []cases{
				{
					name:        "zero key",
					key:         make([]byte, 32),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name:        "key size 15, invalid key size",
					key:         generateKey(t, 15),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
				{
					name:        "key size 23, invalid key size",
					key:         generateKey(t, 23),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
				{
					name:        "key size 33, invalid key size",
					key:         generateKey(t, 33),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "invalid key size",
				},
				{
					name: 	  "wrong ciphertext size",
					key: 	  generateKey(t, 32),
					payload:  generateKey(t, 11),
					expectedErr: "ciphertext too short",
				},
				{
					name: 	  "non-decryptable payload",
					key: 	  generateKey(t, 32),
					payload:  generateKey(t, 32),
					expectedErr: "cipher: message authentication failed",
				},
			},
		},
		{
			name: "AES-GCM-AAD",
			sym: &symmetric.AesGCM{
				AdditionalData: []byte("AAD"),
			},
			decrypt: []cases{
				{
					name: 	  "non-decryptable payload",
					key: 	  generateKey(t, 32),
					payload:  generateKey(t, 32),
					expectedErr: "cipher: message authentication failed",
				},
			},
		},
		{
			name: "XChaCha20",
			sym:  &symmetric.XChaCha20{},
			encrypt: []cases{
				{
					name:        "zero key",
					key:         make([]byte, 32),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name:        "wrong key size",
					key:         generateKey(t, 33),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "chacha20poly1305: bad key length",
				},
			},
			decrypt: []cases{
				{
					name:        "zero key",
					key:         make([]byte, 32),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name:        "wrong key size",
					key:         generateKey(t, 33),
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "chacha20poly1305: bad key length",
				},
				{
					name:        "wrong ciphertext size",
					key:         generateKey(t, 32),
					payload:     generateKey(t, 23),
					expectedErr: "ciphertext too short",
				},
				{
					name:        "non-decryptable payload",
					key:         generateKey(t, 32),
					payload:     generateKey(t, 32),
					expectedErr: "chacha20poly1305: message authentication failed",
				},
			},
		},
		{
			name: "XChaCha20-AAD",
			sym: &symmetric.XChaCha20{
				AdditionalData: []byte("AAD"),
			},
			decrypt: []cases{
				{
					name:        "non-decryptable payload",
					key:         generateKey(t, 32),
					payload:     generateKey(t, 32),
					expectedErr: "chacha20poly1305: message authentication failed",
				},
			},
		},
	}

	testCasesStream := []testStructueStream{
		{
			name: "XChaCha20-Stream",
			encrypt: []casesStream{
				{
					name: "zero key",
					sym: &symmetric.XChaCha20Stream{
						Key: make([]byte, 32),
					},
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name: "wrong key size",
					sym: &symmetric.XChaCha20Stream{
						Key: generateKey(t, 31),
					},
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "wrong key size",
				},
			},
			decrypt: []casesStream{
				{
					name: "zero key",
					sym: &symmetric.XChaCha20Stream{
						Key: make([]byte, 32),
					},
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "key is all zero",
				},
				{
					name: "wrong key size",
					sym: &symmetric.XChaCha20Stream{
						Key: generateKey(t, 31),
					},
					payload:     []byte("https://xkcd.com/936/"),
					expectedErr: "wrong key size",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name + "/encryption", func(t *testing.T) {
			for _, c := range tc.encrypt {
				t.Run(c.name, func(t *testing.T) {
					ciphertext, err := tc.sym.Encrypt(c.key, c.payload)
					r.Nil(t, ciphertext)
					r.ErrorContains(t, err, c.expectedErr)
				})
			}
		})
		t.Run(tc.name + "/decryption", func(t *testing.T) {
			for _, c := range tc.decrypt {
				t.Run(c.name, func(t *testing.T) {
					plaintext, err := tc.sym.Decrypt(c.key, c.payload)
					r.Nil(t, plaintext)
					r.ErrorContains(t, err, c.expectedErr)
				})
			}
		})
	}

	for _, tc := range testCasesStream {
		t.Run(tc.name + "/encryption", func(t *testing.T) {
			for _, c := range tc.encrypt {
				t.Run(c.name, func(t *testing.T) {
					out := &bytes.Buffer{}
					in := bytes.NewReader(c.payload)

					err := c.sym.Encrypt(in, out)
					r.ErrorContains(t, err, c.expectedErr)
				})
			}
		})
		t.Run(tc.name + "/decryption", func(t *testing.T) {
			for _, c := range tc.decrypt {
				t.Run(c.name, func(t *testing.T) {
					out := &bytes.Buffer{}
					in := bytes.NewReader(c.payload)

					err := c.sym.Decrypt(in, out)
					r.ErrorContains(t, err, c.expectedErr)
				})
			}
		})
	}

}

func generateKey(t *testing.T, size int) []byte {
	key, err := generic.CSPRNG(int64(size))
	r.NoError(t, err)
	return key
}
