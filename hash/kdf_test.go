package hash_test

import (
	"strings"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	hasher "github.com/D3vl0per/crypt/hash"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestArgon2ID(t *testing.T) {
	data := []byte("Correct Horse Battery Staple")
	salt, err := generic.CSPRNG(16)
	r.NoError(t, err)
	tests := []struct {
		name  string
		argon hasher.Argon2ID
	}{
		{
			name:  "Default parameters",
			argon: hasher.Argon2ID{},
		},
		{
			name: "Custom memory",
			argon: hasher.Argon2ID{
				Memory: 2 * 64 * 1024,
			},
		},
		{
			name: "Custom iterations",
			argon: hasher.Argon2ID{
				Iterations: 4,
			},
		},
		{
			name: "Custom parallelism",
			argon: hasher.Argon2ID{
				Parallelism: 8,
			},
		},
		{
			name: "Custom key length",
			argon: hasher.Argon2ID{
				KeyLen: 1,
			},
		},
		{
			name: "Custom salt",
			argon: hasher.Argon2ID{
				Salt: salt,
			},
		},
		{
			name: "Custom parameters",
			argon: hasher.Argon2ID{
				Memory:      2 * 64 * 1024,
				Iterations:  2,
				Parallelism: 8,
				KeyLen:      64,
				Salt:        salt,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argonString, err := tt.argon.Hash(data)
			r.NoError(t, err)

			t.Log("Argon string: ", argonString)
			parameters, err := tt.argon.ExtractParameters(argonString)
			r.NoError(t, err)
			t.Log("Argon parameters: ", parameters)

			validator := hasher.Argon2ID{
				KeyLen: tt.argon.KeyLen,
			}

			isValid, err := validator.Validate(data, argonString)
			r.NoError(t, err)
			a.True(t, isValid)
		})
	}
}

func TestArgon2IDWrongParameters(t *testing.T) {
	// Wrong parameters
	tests := []struct {
		name        string
		argonString string
		err         string
	}{
		{
			name:        "Fault test, algorithm is argon2i",
			argonString: "$argon2i$v=19$m=10,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, algorithm is argon2d",
			argonString: "$argon2d$v=19$m=10,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, algorithm is sdfgsdfgsf",
			argonString: "$sdfgsdfgsf$v=19$m=10,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, version is 18",
			argonString: "$argon2id$v=18$m=10,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, version is asdasd",
			argonString: "$argon2id$v=asdasd$m=10,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, memory uint32 2^32+1",
			argonString: "$argon2id$v=19$m=4294967297,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "memory parameter parsing error",
		},
		{
			name:        "Fault test, memory uint32 -1",
			argonString: "$argon2id$v=19$m=-1,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, memory NaN",
			argonString: "$argon2id$v=19$m=asdf,t=2,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, iterations uint32 2^32+1",
			argonString: "$argon2id$v=19$m=10,t=4294967297,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "iteration parameter parsing error",
		},
		{
			name:        "Fault test, iterations uint32 -1",
			argonString: "$argon2id$v=19$m=10,t=-1,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, iteration NaN",
			argonString: "$argon2id$v=19$m=10,t=asd,p=1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, parallelism uint8 2^8+1",
			argonString: "$argon2id$v=19$m=10,t=2,p=256$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "parallelism parameter parsing error",
		},
		{
			name:        "Fault test, parallelism uint8 -1",
			argonString: "$argon2id$v=19$m=10,t=2,p=-1$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, parallelism NaN",
			argonString: "$argon2id$v=19$m=10,t=2,p=asr$SVJYMU1hdXB4czFTT3E4dw$+KPtJ/q0tnhCck+sbDva6g",
			err:         "invalid input format",
		},
		{
			name:        "Fault test, salt is shorter than 16 bytes",
			argonString: "$argon2id$v=19$m=10,t=2,p=1$pB2aWKPIqITWA7tofI9y$+KPtJ/q0tnhCck+sbDva6g",
			err:         "salt must be 16 byte long",
		},
	}

	argon := hasher.Argon2ID{}
	for _, tt := range tests {	
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Log("Test name: ", tt.name)
			t.Log("Argon string: ", tt.argonString)

			parameters, err := argon.ExtractParameters(tt.argonString)
			if err != nil {
				r.True(t, strings.Contains(err.Error(), tt.err))
			} else {
				t.Log("Argon parameters: ", parameters)

				isValid, err := argon.Validate([]byte{}, tt.argonString)
				a.False(t, isValid)

				r.True(t, strings.Contains(err.Error(), tt.err))
			}
		})
	}
}

func TestWrongValidate(t *testing.T) {
	a := hasher.Argon2ID{}
	_, err := a.Validate([]byte("data"), "invalid argonString")
	r.Error(t, err)
}

func TestWrongHash(t *testing.T) {
	a := hasher.Argon2ID{
		Salt: make([]byte, 15),
	}
	_, err := a.Hash([]byte("data"))
	r.Error(t, err)
	r.ErrorContains(t, err, "salt must be 16 byte long")
}

func TestWrongExtractParameters(t *testing.T) {
	a := &hasher.Argon2ID{}

	t.Run("invalid input format", func(t *testing.T) {
		_, err := a.ExtractParameters("invalid input")
		r.Error(t, err)
		r.Equal(t, "invalid input format", err.Error())
	})

	t.Run("hash base64 decode error", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=65536,t=2,p=1$ZU93MDU4TGZ3SGt2Z1NLZA$#####")
		r.Error(t, err)
		r.ErrorContains(t, err, "hash base64 decode error")
	})

	t.Run("salt must be 16 byte long", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=65536,t=2,p=1$invalid$Nc7/+V0dGlljrWU8on8w6w")
		r.Error(t, err)
		r.ErrorContains(t, err, "salt must be 16 byte long")
	})

	t.Run("salt base64 decode error:", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=65536,t=2,p=1$shortsalt$Nc7/+V0dGlljrWU8on8w6w")
		r.Error(t, err)
		r.ErrorContains(t, err, "salt base64 decode error: illegal base64 data at input byte")
	})

	t.Run("iteration parameter parsing error, invalid input format", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=65536,t=invalid,p=1$ZU93MDU4TGZ3SGt2Z1NLZA$Nc7/+V0dGlljrWU8on8w6w")
		r.Error(t, err)
		r.ErrorContains(t, err, "invalid input format")
	})

	t.Run("parallelism parameter parsing error, invalid input format", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=65536,t=2,p=invalid$ZU93MDU4TGZ3SGt2Z1NLZA$Nc7/+V0dGlljrWU8on8w6w")
		r.Error(t, err)
		r.ErrorContains(t, err, "invalid input format")
	})

	t.Run("memory parameter parsing error, invalid input format", func(t *testing.T) {
		_, err := a.ExtractParameters("$argon2id$v=19$m=invalid,t=2,p=1$ZU93MDU4TGZ3SGt2Z1NLZA$Nc7/+V0dGlljrWU8on8w6w")
		r.Error(t, err)
		r.ErrorContains(t, err, "invalid input format")
	})
}

/*
func TestHKDF(t *testing.T) {
	secret := []byte("Correct Horse Battery Staple")
	msg := []byte("https://xkcd.com/936/")

	kdf, err := hash.HKDF(secret, msg)
	r.NoError(t, err)

	isValid, err := hash.HKDFVerify(secret, msg, kdf.Salt, kdf.Hash)
	r.NoError(t, err)
	a.True(t, isValid)
}
*/
/*
func TestHKDFCustomSalt(t *testing.T) {
	secret := []byte("Correct Horse Battery Staple")
	msg := []byte("https://xkcd.com/936/")
	salt, err := CSPRNG(32)
	assert.Nil(t, err)

	kdf, err := HKDFCustomSalt(secret, msg, salt)
	assert.Nil(t, err)

	isValid, err := HKDFVerify(secret, msg, kdf.Salt, kdf.Hash)
	assert.Nil(t, err)
	assert.True(t, isValid)

	isValid, err = HKDFVerify(secret, msg, hex.EncodeToString(salt), kdf.Hash)
	assert.Nil(t, err)
	assert.True(t, isValid)
}
*/
