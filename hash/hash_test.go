package hash_test

import (
	// "encoding/hex".
	"encoding/hex"
	"strings"
	"testing"

	hasher "github.com/D3vl0per/crypt/hash"
	// a "github.com/stretchr/testify/assert".
	r "github.com/stretchr/testify/require"
)

func TestBlakes(t *testing.T) {
	tests := []struct {
		name     string
		algo     hasher.Algorithms
		data     []byte
		expected []byte
	}{
		{
			name: "Blake2b256",
			algo: &hasher.Blake2b256{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{32, 109, 96, 136, 177, 62, 96, 1, 20, 103, 183, 90, 60, 235, 88, 246, 192, 122, 156, 107, 186, 36, 51, 3, 141, 52, 76, 81, 98, 229, 179, 237},
		},
		{
			name: "Blake2b256 HMAC",
			algo: &hasher.Blake2b256{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{141, 216, 41, 55, 227, 130, 65, 74, 238, 19, 155, 174, 22, 46, 103, 68, 212, 184, 176, 225, 176, 182, 94, 11, 128, 55, 85, 127, 136, 105, 14, 169},
		},
		{
			name: "Blake2b384",
			algo: &hasher.Blake2b384{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{50, 67, 235, 235, 146, 164, 58, 187, 5, 182, 182, 179, 132, 31, 200, 27, 68, 50, 83, 71, 221, 131, 86, 164, 203, 194, 251, 64, 172, 45, 105, 200, 90, 118, 50, 47, 37, 237, 28, 153, 88, 166, 95, 221, 138, 249, 176, 116},
		},
		{
			name: "Blake2b384 HMAC",
			algo: &hasher.Blake2b384{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{2, 58, 228, 49, 225, 253, 51, 171, 34, 190, 207, 112, 186, 131, 0, 65, 58, 117, 119, 182, 72, 69, 151, 185, 128, 227, 180, 137, 5, 39, 172, 99, 21, 102, 79, 245, 62, 180, 104, 244, 218, 233, 60, 57, 161, 15, 31, 169},
		},
		{
			name: "Blake2b512",
			algo: &hasher.Blake2b512{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{119, 40, 57, 190, 223, 104, 229, 179, 37, 38, 116, 236, 59, 79, 64, 38, 242, 100, 128, 101, 147, 40, 14, 159, 186, 100, 251, 182, 206, 58, 244, 200, 26, 133, 123, 65, 131, 213, 220, 248, 152, 111, 73, 93, 126, 181, 139, 26, 48, 40, 254, 156, 254, 108, 19, 47, 92, 67, 209, 60, 127, 148, 155, 39},
		},
		{
			name: "Blake2b512 HMAC",
			algo: &hasher.Blake2b512{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{216, 241, 59, 128, 75, 177, 73, 147, 208, 198, 138, 37, 187, 128, 230, 173, 60, 117, 96, 33, 223, 55, 143, 219, 51, 47, 108, 67, 98, 0, 159, 197, 24, 112, 56, 191, 150, 82, 9, 225, 89, 0, 213, 168, 81, 69, 18, 10, 189, 249, 143, 31, 55, 119, 242, 126, 205, 253, 41, 158, 156, 30, 188, 105},
		},
		{
			name: "SHA3-256",
			algo: &hasher.Sha3256{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{195, 62, 41, 181, 107, 38, 110, 3, 129, 21, 52, 217, 117, 49, 247, 163, 218, 89, 94, 205, 254, 161, 207, 196, 114, 73, 155, 161, 61, 38, 229, 59},
		},
		{
			name: "SHA3-384",
			algo: &hasher.Sha3384{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{13, 164, 89, 48, 108, 199, 207, 244, 184, 228, 229, 210, 233, 175, 29, 85, 79, 200, 21, 45, 82, 193, 210, 227, 195, 78, 6, 230, 102, 127, 126, 121, 118, 120, 44, 105, 214, 238, 75, 46, 166, 133, 61, 161, 228, 2, 6, 46},
		},
		{
			name: "SHA3-512",
			algo: &hasher.Sha3512{},
			data: []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh"),
			//nolint:lll
			expected: []byte{125, 21, 172, 36, 13, 53, 250, 136, 28, 214, 188, 8, 227, 249, 19, 86, 128, 200, 212, 106, 225, 41, 67, 3, 81, 115, 58, 187, 209, 129, 44, 191, 163, 205, 134, 207, 246, 127, 72, 31, 9, 11, 33, 184, 131, 16, 44, 152, 2, 55, 71, 215, 195, 73, 233, 147, 80, 13, 79, 131, 146, 100, 38, 202},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if strings.Contains(test.name, "HMAC") {
				hash, err := test.algo.Hmac(test.data)
				r.NoError(t, err)
				t.Log("Hash: ", hex.EncodeToString(hash))
				r.Equal(t, test.expected, hash)

				validate, err := test.algo.ValidateHmac(test.data, hash)
				r.NoError(t, err)
				r.True(t, validate)
			} else {
				hash, err := test.algo.Hash(test.data)
				r.NoError(t, err)
				t.Log("Hash: ", hex.EncodeToString(hash))
				r.Equal(t, test.expected, hash)

				validate, err := test.algo.ValidateHash(test.data, hash)
				r.NoError(t, err)
				r.True(t, validate)
			}
		})
	}
}

func TestFaultBlakes(t *testing.T) {
	tests := []struct {
		name     string
		algo     hasher.Algorithms
		data     []byte
		expected []byte
	}{
		{
			name: "Blake2b256",
			algo: &hasher.Blake2b256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{32, 109, 96, 136, 177, 62, 96, 1, 20, 103, 183, 90, 60, 235, 88, 246, 192, 122, 156, 107, 186, 36, 51, 3, 141, 52, 76, 81, 98, 229, 179, 237},
		},
		{
			name: "Blake2b256 HMAC",
			algo: &hasher.Blake2b256{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{141, 216, 41, 55, 227, 130, 65, 74, 238, 19, 155, 174, 22, 46, 103, 68, 212, 184, 176, 225, 176, 182, 94, 11, 128, 55, 85, 127, 136, 105, 14, 169},
		},
		{
			name: "Blake2b384",
			algo: &hasher.Blake2b384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{50, 67, 235, 235, 146, 164, 58, 187, 5, 182, 182, 179, 132, 31, 200, 27, 68, 50, 83, 71, 221, 131, 86, 164, 203, 194, 251, 64, 172, 45, 105, 200, 90, 118, 50, 47, 37, 237, 28, 153, 88, 166, 95, 221, 138, 249, 176, 116},
		},
		{
			name: "Blake2b384 HMAC",
			algo: &hasher.Blake2b384{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{2, 58, 228, 49, 225, 253, 51, 171, 34, 190, 207, 112, 186, 131, 0, 65, 58, 117, 119, 182, 72, 69, 151, 185, 128, 227, 180, 137, 5, 39, 172, 99, 21, 102, 79, 245, 62, 180, 104, 244, 218, 233, 60, 57, 161, 15, 31, 169},
		},
		{
			name: "Blake2b512",
			algo: &hasher.Blake2b512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{119, 40, 57, 190, 223, 104, 229, 179, 37, 38, 116, 236, 59, 79, 64, 38, 242, 100, 128, 101, 147, 40, 14, 159, 186, 100, 251, 182, 206, 58, 244, 200, 26, 133, 123, 65, 131, 213, 220, 248, 152, 111, 73, 93, 126, 181, 139, 26, 48, 40, 254, 156, 254, 108, 19, 47, 92, 67, 209, 60, 127, 148, 155, 39},
		},
		{
			name: "Blake2b512 HMAC",
			algo: &hasher.Blake2b512{
				HmacSecret: []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633"),
			},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{216, 241, 59, 128, 75, 177, 73, 147, 208, 198, 138, 37, 187, 128, 230, 173, 60, 117, 96, 33, 223, 55, 143, 219, 51, 47, 108, 67, 98, 0, 159, 197, 24, 112, 56, 191, 150, 82, 9, 225, 89, 0, 213, 168, 81, 69, 18, 10, 189, 249, 143, 31, 55, 119, 242, 126, 205, 253, 41, 158, 156, 30, 188, 105},
		},
		{
			name: "SHA3-256",
			algo: &hasher.Sha3256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{195, 62, 41, 181, 107, 38, 110, 3, 129, 21, 52, 217, 117, 49, 247, 163, 218, 89, 94, 205, 254, 161, 207, 196, 114, 73, 155, 161, 61, 38, 229, 59},
		},
		{
			name: "SHA3-384",
			algo: &hasher.Sha3384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{13, 164, 89, 48, 108, 199, 207, 244, 184, 228, 229, 210, 233, 175, 29, 85, 79, 200, 21, 45, 82, 193, 210, 227, 195, 78, 6, 230, 102, 127, 126, 121, 118, 120, 44, 105, 214, 238, 75, 46, 166, 133, 61, 161, 228, 2, 6, 46},
		},
		{
			name: "SHA3-512",
			algo: &hasher.Sha3512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{125, 21, 172, 36, 13, 53, 250, 136, 28, 214, 188, 8, 227, 249, 19, 86, 128, 200, 212, 106, 225, 41, 67, 3, 81, 115, 58, 187, 209, 129, 44, 191, 163, 205, 134, 207, 246, 127, 72, 31, 9, 11, 33, 184, 131, 16, 44, 152, 2, 55, 71, 215, 195, 73, 233, 147, 80, 13, 79, 131, 146, 100, 38, 202},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.name, "HMAC") {
				validate, err := test.algo.ValidateHash(test.data, test.expected)
				r.NoError(t, err)
				r.False(t, validate)
			} else {
				validate, err := test.algo.ValidateHmac(test.data, test.expected)
				r.NoError(t, err)
				r.False(t, validate)
			}
		})
	}
}

func TestNilKeyError(t *testing.T) {
	tests := []struct {
		name     string
		algo     hasher.Algorithms
		data     []byte
		expected []byte
	}{
		{
			name: "Blake2b256 HMAC",
			algo: &hasher.Blake2b256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{141, 216, 41, 55, 227, 130, 65, 74, 238, 19, 155, 174, 22, 46, 103, 68, 212, 184, 176, 225, 176, 182, 94, 11, 128, 55, 85, 127, 136, 105, 14, 169},
		},
		{
			name: "Blake2b384 HMAC",
			algo: &hasher.Blake2b384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{2, 58, 228, 49, 225, 253, 51, 171, 34, 190, 207, 112, 186, 131, 0, 65, 58, 117, 119, 182, 72, 69, 151, 185, 128, 227, 180, 137, 5, 39, 172, 99, 21, 102, 79, 245, 62, 180, 104, 244, 218, 233, 60, 57, 161, 15, 31, 169},
		},
		{
			name: "Blake2b512 HMAC",
			algo: &hasher.Blake2b512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{216, 241, 59, 128, 75, 177, 73, 147, 208, 198, 138, 37, 187, 128, 230, 173, 60, 117, 96, 33, 223, 55, 143, 219, 51, 47, 108, 67, 98, 0, 159, 197, 24, 112, 56, 191, 150, 82, 9, 225, 89, 0, 213, 168, 81, 69, 18, 10, 189, 249, 143, 31, 55, 119, 242, 126, 205, 253, 41, 158, 156, 30, 188, 105},
		},
		{
			name: "SHA3-256 HMAC",
			algo: &hasher.Sha3256{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{195, 62, 41, 181, 107, 38, 110, 3, 129, 21, 52, 217, 117, 49, 247, 163, 218, 89, 94, 205, 254, 161, 207, 196, 114, 73, 155, 161, 61, 38, 229, 59},
		},
		{
			name: "SHA3-384 HMAC",
			algo: &hasher.Sha3384{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{13, 164, 89, 48, 108, 199, 207, 244, 184, 228, 229, 210, 233, 175, 29, 85, 79, 200, 21, 45, 82, 193, 210, 227, 195, 78, 6, 230, 102, 127, 126, 121, 118, 120, 44, 105, 214, 238, 75, 46, 166, 133, 61, 161, 228, 2, 6, 46},
		},
		{
			name: "SHA3-512 HMAC",
			algo: &hasher.Sha3512{},
			data: []byte("aing7jei3eebeaMohjeesheeph0ichaiXual4vah1Eeg3eikai7aichoeliej1da"),
			//nolint:lll
			expected: []byte{125, 21, 172, 36, 13, 53, 250, 136, 28, 214, 188, 8, 227, 249, 19, 86, 128, 200, 212, 106, 225, 41, 67, 3, 81, 115, 58, 187, 209, 129, 44, 191, 163, 205, 134, 207, 246, 127, 72, 31, 9, 11, 33, 184, 131, 16, 44, 152, 2, 55, 71, 215, 195, 73, 233, 147, 80, 13, 79, 131, 146, 100, 38, 202},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, err := test.algo.Hmac(test.data)
			r.ErrorIs(t, err, hasher.ErrHmacSecretNil)
			r.Empty(t, hash)

			validate, err := test.algo.ValidateHmac(test.data, test.expected)
			r.ErrorIs(t, err, hasher.ErrHmacSecretNil)
			r.False(t, validate)
		})
	}
}
