package hash

import (
	"encoding/base64"
	"errors"
	"hash"
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

type Hkdf struct {
	Salt     []byte
	Key      []byte
	HashMode func() hash.Hash
	Encoder  generic.Hex
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

	// Set default values
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

	if len(a.Salt) == 0 {
		a.Salt = parameters.Salt
	}

	if a.Iterations == 0 {
		a.Iterations = parameters.Iterations
	}

	if a.Memory == 0 {
		a.Memory = parameters.Memory
	}

	if a.Parallelism == 0 {
		a.Parallelism = parameters.Parallelism
	}

	if a.KeyLen == 0 {
		a.KeyLen = AKeyLen
	}

	hashed := a.argon2ID(data)

	return generic.Compare(hashed.Hash, parameters.Hash), nil
}

type Parameters struct {
	Algorithm   string
	Version     string
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
	Hash        []byte
}

func (a *Argon2ID) ExtractParameters(input string) (Parameters, error) {
	pattern := `\$(argon2id)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`

	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(input)

	if len(matches) != 8 {
		return Parameters{}, errors.New("invalid input format")
	}

	parameters := Parameters{
		Algorithm: matches[1],
		Version:   matches[2],
	}

	if len(parameters.Algorithm) == 0 || !generic.CompareString(parameters.Algorithm, "argon2id") {
		return Parameters{}, errors.New(generic.StrCnct([]string{"invalid algorithm: ", parameters.Algorithm}...))
	}

	if len(parameters.Version) == 0 || !generic.CompareString(parameters.Version, strconv.FormatInt(int64(argon2.Version), 10)) {
		return Parameters{}, errors.New(generic.StrCnct([]string{"invalid version: ", parameters.Version}...))
	}

	var err error

	parameters.Hash, err = base64.RawStdEncoding.DecodeString(matches[7])
	if err != nil {
		return Parameters{}, errors.New(generic.StrCnct([]string{"hash base64 decode error: ", err.Error()}...))
	}

	parameters.Salt, err = base64.RawStdEncoding.DecodeString(matches[6])
	if err != nil {
		return Parameters{}, errors.New(generic.StrCnct([]string{"salt base64 decode error: ", err.Error()}...))
	}

	memory, err := strconv.ParseInt(matches[3], 10, 32)
	if err != nil {
		return Parameters{}, errors.New(generic.StrCnct([]string{"memory parameter parsing error: ", err.Error()}...))
	}

	parameters.Memory = uint32(memory)

	iterations, err := strconv.ParseInt(matches[4], 10, 32)
	if err != nil {
		return Parameters{}, errors.New(generic.StrCnct([]string{"iteration parameter parsing error: ", err.Error()}...))
	}
	parameters.Iterations = uint32(iterations)

	parallelism, err := strconv.ParseInt(matches[5], 10, 8)
	if err != nil {
		return Parameters{}, errors.New(generic.StrCnct([]string{"parallelism parameter parsing error: ", err.Error()}...))
	}

	parameters.Parallelism = uint8(parallelism)

	return parameters, nil
}

/*
func (h *Hkdf) Hash(data []byte) (string, error) {
	if h.Salt != nil {
		if len(h.Salt) != h.HashMode().Size() {
			return "", errors.New(generic.StrCnct([]string{"salt must be", strconv.Itoa(h.HashMode().Size()), " byte long"}...))
		}
	} else {
		var err error
		h.Salt, err = generic.CSPRNG(int64(h.HashMode().Size()))
		if err != nil {
			return "", err
		}
	}

	if h.HashMode == nil {
		h.HashMode = sha3.New512
	}

	kdf := hkdf.New(h.HashMode, h.Key, h.Salt, data)

	key := make([]byte, HKDFKeysize)

	if _, err := io.ReadFull(kdf, key); err != nil {
		return "", err
	}

	return generic.StrCnct([]string{h.Encoder.Encode(key), "#", h.Encoder.Encode(h.Salt)}...), nil
}

func (h *Hkdf) Validate(data []byte, hash string) (bool, error) {

	if len(h.Salt) == 0 || len(h.Salt) != h.HashMode().Size() {
		return false, errors.New(generic.StrCnct([]string{"salt must be ", strconv.Itoa(h.HashMode().Size()), " byte long"}...))
	}

	if h.HashMode == nil {
		h.HashMode = sha3.New512
	}

	kdf := hkdf.New(h.HashMode, h.Key, h.Salt, data)

	key := make([]byte, HKDFKeysize)

	if _, err := io.ReadFull(kdf, key); err != nil {
		return false, err
	}

	hash_raw, err := h.Encoder.Decode(hash)
	if err != nil {
		return false, err
	}

	return generic.Compare(hash_raw, h.Salt), nil
}
*/
