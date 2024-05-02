package hash_test

import (
	// "encoding/hex".

	"strings"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	hasher "github.com/D3vl0per/crypt/hash"

	// a "github.com/stretchr/testify/assert".
	r "github.com/stretchr/testify/require"
)

var data = []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
var secret = []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633")
var secret32 = secret[:32]

func TestE2EEHash(t *testing.T) {
	encoders := []generic.Encoder{
		nil,
		&generic.Hex{},
		&generic.Base64{},
		&generic.PaddinglessBase32{},
		&generic.RawBase64{},
		&generic.RawURLBase64{},
		&generic.URLBase64{},
		&generic.Base32{},
	}

	hex := generic.Hex{}
	t.Log("Payload data: ", data)
	t.Log("Payload data hex: ", hex.Encode(data))
	t.Log("HMAC secret: ", secret)
	t.Log("HMAC secret hex: ", hex.Encode(secret))
	t.Log("HMAC secret32: ", secret32)
	t.Log("HMAC secret32 hex: ", hex.Encode(secret32))

	tests := []struct {
		name     string
		algo     hasher.Algorithms
		data     []byte
		expected []byte
	}{
		{
			name: "Blake2b256",
			algo: &hasher.Blake2b256{},
			data: data,
			//nolint:lll
			expected: []byte{32, 109, 96, 136, 177, 62, 96, 1, 20, 103, 183, 90, 60, 235, 88, 246, 192, 122, 156, 107, 186, 36, 51, 3, 141, 52, 76, 81, 98, 229, 179, 237},
		},
		{
			name: "Blake2b256 HMAC",
			algo: &hasher.Blake2b256{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{141, 216, 41, 55, 227, 130, 65, 74, 238, 19, 155, 174, 22, 46, 103, 68, 212, 184, 176, 225, 176, 182, 94, 11, 128, 55, 85, 127, 136, 105, 14, 169},
		},
		{
			name: "Blake2b384",
			algo: &hasher.Blake2b384{},
			data: data,
			//nolint:lll
			expected: []byte{50, 67, 235, 235, 146, 164, 58, 187, 5, 182, 182, 179, 132, 31, 200, 27, 68, 50, 83, 71, 221, 131, 86, 164, 203, 194, 251, 64, 172, 45, 105, 200, 90, 118, 50, 47, 37, 237, 28, 153, 88, 166, 95, 221, 138, 249, 176, 116},
		},
		{
			name: "Blake2b384 HMAC",
			algo: &hasher.Blake2b384{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{2, 58, 228, 49, 225, 253, 51, 171, 34, 190, 207, 112, 186, 131, 0, 65, 58, 117, 119, 182, 72, 69, 151, 185, 128, 227, 180, 137, 5, 39, 172, 99, 21, 102, 79, 245, 62, 180, 104, 244, 218, 233, 60, 57, 161, 15, 31, 169},
		},
		{
			name: "Blake2b512",
			algo: &hasher.Blake2b512{},
			data: data,
			//nolint:lll
			expected: []byte{119, 40, 57, 190, 223, 104, 229, 179, 37, 38, 116, 236, 59, 79, 64, 38, 242, 100, 128, 101, 147, 40, 14, 159, 186, 100, 251, 182, 206, 58, 244, 200, 26, 133, 123, 65, 131, 213, 220, 248, 152, 111, 73, 93, 126, 181, 139, 26, 48, 40, 254, 156, 254, 108, 19, 47, 92, 67, 209, 60, 127, 148, 155, 39},
		},
		{
			name: "Blake2b512 HMAC",
			algo: &hasher.Blake2b512{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{216, 241, 59, 128, 75, 177, 73, 147, 208, 198, 138, 37, 187, 128, 230, 173, 60, 117, 96, 33, 223, 55, 143, 219, 51, 47, 108, 67, 98, 0, 159, 197, 24, 112, 56, 191, 150, 82, 9, 225, 89, 0, 213, 168, 81, 69, 18, 10, 189, 249, 143, 31, 55, 119, 242, 126, 205, 253, 41, 158, 156, 30, 188, 105},
		},
		{
			name: "Blake2s128 HMAC",
			algo: &hasher.Blake2s128{
				HmacSecret: secret32,
			},
			data: data,
			//nolint:lll
			expected: []byte{204, 223, 167, 35, 204, 181, 41, 228, 92, 241, 138, 3, 213, 17, 7, 81},
		},
		{
			name: "Blake2s256",
			algo: &hasher.Blake2s256{},
			data: data,
			//nolint:lll
			expected: []byte{253, 217, 52, 13, 209, 19, 73, 9, 94, 71, 87, 116, 120, 39, 24, 139, 188, 232, 38, 39, 97, 105, 224, 60, 166, 85, 30, 119, 95, 71, 2, 73},
		},
		{
			name: "Blake2s256 HMAC",
			algo: &hasher.Blake2s256{
				HmacSecret: secret32,
			},
			data: data,
			//nolint:lll
			expected: []byte{25, 46, 167, 48, 46, 109, 25, 171, 41, 52, 149, 122, 253, 252, 4, 155, 206, 91, 99, 158, 23, 24, 170, 140, 103, 102, 97, 34, 100, 100, 78, 246},
		},
		{
			name: "SHA2-256",
			algo: &hasher.Sha2256{},
			data: data,
			//nolint:lll
			expected: []byte{238, 55, 33, 27, 215, 100, 195, 216, 24, 127, 149, 250, 72, 255, 105, 200, 31, 209, 23, 74, 254, 94, 102, 83, 0, 27, 13, 143, 186, 14, 226, 201},
		},
		{
			name: "SHA2-256 HMAC",
			algo: &hasher.Sha2256{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{242, 206, 236, 41, 173, 161, 171, 182, 232, 138, 25, 200, 134, 212, 129, 3, 170, 130, 200, 64, 245, 55, 151, 63, 164, 66, 174, 215, 203, 224, 47, 138},
		},
		{
			name: "SHA2-384",
			algo: &hasher.Sha2384{},
			data: data,
			//nolint:lll
			expected: []byte{45, 57, 162, 221, 210, 25, 23, 42, 193, 211, 61, 74, 45, 73, 232, 137, 16, 174, 128, 114, 111, 127, 172, 11, 123, 121, 184, 200, 232, 137, 146, 138, 148, 57, 87, 80, 67, 173, 182, 44, 159, 3, 214, 159, 170, 102, 63, 151},
		},
		{
			name: "SHA2-384 HMAC",
			algo: &hasher.Sha2384{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{47, 180, 143, 233, 227, 244, 166, 28, 236, 156, 33, 106, 110, 15, 185, 1, 251, 231, 45, 39, 115, 121, 140, 103, 181, 213, 172, 151, 6, 218, 191, 187, 229, 198, 248, 209, 255, 172, 134, 25, 255, 186, 233, 147, 75, 36, 83, 6},
		},
		{
			name: "SHA2-512",
			algo: &hasher.Sha2512{},
			data: data,
			//nolint:lll
			expected: []byte{47, 203, 64, 53, 6, 59, 136, 223, 254, 248, 36, 98, 124, 160, 88, 169, 8, 157, 203, 143, 230, 66, 76, 58, 222, 108, 141, 3, 246, 88, 57, 139, 166, 224, 186, 137, 224, 82, 243, 140, 151, 23, 128, 151, 46, 49, 30, 175, 133, 138, 54, 123, 19, 186, 36, 248, 16, 47, 74, 44, 56, 47, 4, 41},
		},
		{
			name: "SHA2-512 HMAC",
			algo: &hasher.Sha2512{
				HmacSecret: secret,
			},
			data: data,
			//nolint:lll
			expected: []byte{7, 12, 136, 242, 52, 34, 149, 21, 90, 179, 201, 78, 111, 162, 72, 47, 57, 9, 20, 251, 41, 53, 34, 150, 35, 230, 251, 143, 10, 213, 105, 145, 163, 98, 112, 26, 5, 6, 150, 217, 149, 163, 249, 18, 101, 241, 179, 141, 239, 123, 34, 34, 94, 200, 237, 216, 15, 167, 204, 82, 211, 17, 63, 235},
		},
		{
			name: "SHA3-256",
			algo: &hasher.Sha3256{},
			data: data,
			//nolint:lll
			expected: []byte{195, 62, 41, 181, 107, 38, 110, 3, 129, 21, 52, 217, 117, 49, 247, 163, 218, 89, 94, 205, 254, 161, 207, 196, 114, 73, 155, 161, 61, 38, 229, 59},
		},
		{
			name: "SHA3-384",
			algo: &hasher.Sha3384{},
			data: data,
			//nolint:lll
			expected: []byte{13, 164, 89, 48, 108, 199, 207, 244, 184, 228, 229, 210, 233, 175, 29, 85, 79, 200, 21, 45, 82, 193, 210, 227, 195, 78, 6, 230, 102, 127, 126, 121, 118, 120, 44, 105, 214, 238, 75, 46, 166, 133, 61, 161, 228, 2, 6, 46},
		},
		{
			name: "SHA3-512",
			algo: &hasher.Sha3512{},
			data: data,
			//nolint:lll
			expected: []byte{125, 21, 172, 36, 13, 53, 250, 136, 28, 214, 188, 8, 227, 249, 19, 86, 128, 200, 212, 106, 225, 41, 67, 3, 81, 115, 58, 187, 209, 129, 44, 191, 163, 205, 134, 207, 246, 127, 72, 31, 9, 11, 33, 184, 131, 16, 44, 152, 2, 55, 71, 215, 195, 73, 233, 147, 80, 13, 79, 131, 146, 100, 38, 202},
		},
	}

	for _, test := range tests {
		for _, encoder := range encoders {
			test.algo.SetEncoder(encoder)
			testName := test.name
			if encoder != nil {
				testName = test.name + "/" + encoder.GetName()
			}

			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				if strings.Contains(test.name, "HMAC") {
					hash, err := test.algo.Hmac(test.data)
					r.NoError(t, err)
					t.Log("Raw hash: ", string(hash))

					hash, err = decoder(test.algo, hash)
					r.NoError(t, err)
					r.Equal(t, test.expected, hash)

					validate, err := test.algo.ValidateHmac(test.data, hash)
					r.NoError(t, err)
					r.True(t, validate)
				} else {
					hash, err := test.algo.Hash(test.data)
					r.NoError(t, err)
					t.Log("Raw hash: ", string(hash))

					hash, err = decoder(test.algo, hash)
					r.NoError(t, err)

					r.Equal(t, test.expected, hash)

					validate, err := test.algo.ValidateHash(test.data, hash)
					r.NoError(t, err)
					r.True(t, validate)
				}
			})
		}
	}
}

func decoder(algo hasher.Algorithms, hashed []byte) ([]byte, error) {
	if algo.GetEncoder() != nil {
		hash, err := algo.GetEncoder().Decode(string(hashed))
		if err != nil {
			return nil, err
		}
		return hash, nil
	}
	return hashed, nil
}

func TestHashErrors(t *testing.T) {
	tests := []struct {
		name string
		algo hasher.Algorithms
		data []byte
		err  error
	}{
		{
			name: "Blake2b256 HMAC",
			algo: &hasher.Blake2b256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "Blake2b384 HMAC",
			algo: &hasher.Blake2b384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "Blake2b512 HMAC",
			algo: &hasher.Blake2b512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		/*{
			name: "Blake2s128",
			algo: &hasher.Blake2s128{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  errors.New("blake2s: a key is required for a 128-bit hash"),
		},*/
		{
			name: "Blake2s128 HMAC",
			algo: &hasher.Blake2s128{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "Blake2s256 HMAC",
			algo: &hasher.Blake2b256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA2-256 HMAC",
			algo: &hasher.Sha2256{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA2-384 HMAC",
			algo: &hasher.Sha2384{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA2-512 HMAC",
			algo: &hasher.Sha2512{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA3-256 HMAC",
			algo: &hasher.Sha3256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA3-384 HMAC",
			algo: &hasher.Sha3384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
		{
			name: "SHA3-512 HMAC",
			algo: &hasher.Sha3512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			err:  hasher.ErrHmacSecretNil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if strings.Contains(test.name, "HMAC") {
				hash, err := test.algo.Hmac(test.data)
				r.ErrorIs(t, err, test.err)
				r.Empty(t, hash)

				validate, err := test.algo.ValidateHmac(test.data, hash)
				r.ErrorIs(t, err, test.err)
				r.False(t, validate)
			} else {
				hash, err := test.algo.Hash(test.data)
				r.ErrorIs(t, err, test.err)
				r.Empty(t, hash)

				validate, err := test.algo.ValidateHash(test.data, hash)
				r.ErrorIs(t, err, test.err)
				r.False(t, validate)
			}
		})
	}
}
