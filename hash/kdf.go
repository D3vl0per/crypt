package hash

import (
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strconv"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/argon2"
)

const (
	AIterations  uint32 = 2
	AMemory      uint32 = 1 * 64 * 1024
	AParallelism uint8  = 4
	AKeyLen      uint32 = 32
	HKDFKeysize  int    = 32
)

type Kdf interface {
	Hash([]byte) (string, error)
	Validate([]byte, string) (bool, error)
}

type Argon2ID struct {
	Salt        []byte
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLen      uint32
}

type argonOutput struct {
	ArgonString string
	Hash        []byte
	HashBase64  string
	Salt        []byte
	SaltBase64  string
}

func (a *Argon2ID) argon2ID(data []byte) argonOutput {
	hash := argon2.IDKey(data, a.Salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLen)

	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	saltB64 := base64.RawStdEncoding.EncodeToString(a.Salt)

	argonString := generic.StrCnct([]string{
		"$argon2id$v=", strconv.FormatInt(int64(argon2.Version), 10),
		"$m=", strconv.FormatUint(uint64(a.Memory), 10),
		",t=", strconv.FormatUint(uint64(a.Iterations), 10),
		",p=", strconv.FormatInt(int64(a.Parallelism), 10),
		"$", saltB64,
		"$", hashB64}...,
	)

	return argonOutput{
		ArgonString: argonString,
		Hash:        hash,
		HashBase64:  hashB64,
		Salt:        a.Salt,
		SaltBase64:  saltB64,
	}
}

func (a *Argon2ID) Hash(data []byte) (string, error) {
	if a.Salt != nil {
		if len(a.Salt) != 16 {
			return "", errors.New("salt must be 16 byte long")
		}
	} else {
		var err error
		a.Salt, err = generic.CSPRNG(16)
		if err != nil {
			return "", err
		}
	}

	a.Iterations |= AIterations
	a.Memory |= AMemory
	a.Parallelism |= AParallelism
	a.KeyLen |= AKeyLen

	output := a.argon2ID(data)
	return output.ArgonString, nil
}

func (a *Argon2ID) Validate(data []byte, argonString string) (bool, error) {
	parameters, err := a.ExtractParameters(argonString)
	if err != nil {
		return false, err
	}

	providedHash, err := base64.RawStdEncoding.DecodeString(parameters["hash"])
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"hash base64 decode error: ", err.Error()}...))
	}

	a.Salt, err = base64.RawStdEncoding.DecodeString(parameters["salt"])
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"salt base64 decode error: ", err.Error()}...))
	}

	if a.Iterations == 0 {
		parsed, err := strconv.ParseUint(parameters["iterations"], 10, 32)
		if err != nil {
			return false, errors.New(generic.StrCnct([]string{"iteration parameter parsing error: ", err.Error()}...))
		}
		a.Iterations = uint32(parsed)
	}

	if a.Memory == 0 {
		parsed, err := strconv.ParseUint(parameters["memory"], 10, 32)
		if err != nil {
			return false, errors.New(generic.StrCnct([]string{"memory parameter parsing error: ", err.Error()}...))
		}
		a.Memory = uint32(parsed)
	}

	if a.Parallelism == 0 {
		parsed, err := strconv.ParseUint(parameters["parallelism"], 10, 32)
		if err != nil {
			return false, errors.New(generic.StrCnct([]string{"parallelism parameter parsing error: ", err.Error()}...))
		}
		if parsed > 0 && parsed <= math.MaxInt32 {
			a.Parallelism = uint8(parsed)
		} else {
			return false, errors.New("parallelism parameter parsing error, can't parse that number")
		}
	}

	if a.KeyLen == 0 {
		a.KeyLen = AKeyLen
	}

	hashed := a.argon2ID(data)

	return generic.Compare(hashed.Hash, providedHash), nil
}

/*
	type Hkdf struct {
		Salt []byte
		Secret []byte
		HashMode   func() hash.Hash
	}

// Easy to user HKDF toolset.

	func (h *Hkdf) Hash(data []byte) ([]byte, error) {
		kdf := hkdf.New(h.HashMode, h.Secret, h.Salt, data)

		key := make([]byte, HKDFKeysize)

		if _, err := io.ReadFull(kdf, key); err != nil {
			return []byte{}, err
		}
		return key, nil
	}

	func HKDFRecreate(secret, msg []byte, salt string) ([]byte, error) {
		salt_raw, err := hex.DecodeString(salt)
		if err != nil {
			return []byte{}, err
		}

		return HKDFBase(secret, salt_raw, msg)
	}

	func HKDF(secret, msg []byte) (keys, error) {
		hash := sha256.New
		salt, err := generic.CSPRNG(int64(hash().Size()))
		if err != nil {
			return keys{}, err
		}

		key, err := HKDFBase(secret, salt, msg)
		if err != nil {
			return keys{}, err
		}

		return keys{
			Salt: hex.EncodeToString(salt),
			Hash: hex.EncodeToString(key),
		}, nil
	}

	func HKDFVerify(secret, msg []byte, salt, hash string) (bool, error) {
		hash_to_validate, err := HKDFRecreate(secret, msg, salt)
		if err != nil {
			return false, err
		}

		hash_raw, err := hex.DecodeString(hash)
		if err != nil {
			return false, err
		}

		return generic.Compare(hash_raw, hash_to_validate), nil
	}
*/

func (a *Argon2ID) ExtractParameters(input string) (map[string]string, error) {
	pattern := `\$(argon2id)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`

	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(input)

	if len(matches) != 8 {
		return nil, errors.New("invalid input format")
	}

	parameters := map[string]string{
		"algorithm":   matches[1],
		"version":     matches[2],
		"memory":      matches[3],
		"iterations":  matches[4],
		"parallelism": matches[5],
		"salt":        matches[6],
		"hash":        matches[7],
	}

	if len(parameters["algorithm"]) == 0 || parameters["algorithm"] != "argon2id" {
		return map[string]string{}, errors.New(generic.StrCnct([]string{"invalid algorithm: ", parameters["algorithm"]}...))
	}

	if len(parameters["version"]) == 0 || parameters["version"] != strconv.FormatInt(int64(argon2.Version), 10) {
		return map[string]string{}, errors.New(generic.StrCnct([]string{"invalid version: ", parameters["version"]}...))
	}

	if len(parameters["hash"]) == 0 {
		return map[string]string{}, errors.New("missing hash")
	}

	if len(parameters["salt"]) == 0 {
		return map[string]string{}, errors.New("missing salt")
	}

	return parameters, nil
}
