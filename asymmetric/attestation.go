package asymmetric

import (
	"errors"
	"strings"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/hash"
)

type Attestation interface {
	Sign([]byte) (string, error)
	Verify(string) (bool, error)
	Parse(string) (string, error)
}

type Minimalistic struct {
	Suite         Signing
	Hasher        hash.Algorithms
	Serialization Serializers
	Encoder       generic.Encoder
}

func (m *Minimalistic) Sign(payload []byte) (string, error) {

	if m.Suite == nil {
		return "", errors.New("missing signing suite declaration")
	}

	if m.Suite.GetSecretKey() == nil {
		return "", errors.New("missing secret key declaration")
	}

	if m.Encoder == nil {
		m.Encoder = &generic.Hex{}
	}

	if m.Encoder != m.Suite.GetEncoder() {
		return "", errors.New("encoder mismatch between signing suite and attestation")
	}

	if m.Hasher == nil {
		m.Hasher = &hash.Blake2b256{}
	}

	hashedPayload, err := m.Hasher.Hash(payload)
	if err != nil {
		return "", errors.New(generic.StrCnct([]string{"hashing error: ", err.Error()}...))
	}

	signature := m.Suite.Sign(hashedPayload)

	encodedPayload := m.Encoder.Encode(payload)

	token, err := m.Serialization.Serializer(encodedPayload, signature)
	if err != nil {
		return "", errors.New(generic.StrCnct([]string{"serializer error: ", err.Error()}...))
	}
	return token, nil
}

func (m *Minimalistic) Verify(token string) (bool, error) {
	if m.Suite.GetPublicKey() == nil {
		return false, errors.New("missing public key declaration")
	}

	if m.Encoder == nil {
		m.Encoder = &generic.Hex{}
	}

	if m.Encoder != m.Suite.GetEncoder() {
		return false, errors.New("encoder mismatch between signing suite and attestation")
	}

	if m.Hasher == nil {
		m.Hasher = &hash.Blake2b256{}
	}

	payload, signature, err := m.Serialization.Deserializer(token)
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"deserializer error: ", err.Error()}...))
	}

	decodedPayload, err := m.Encoder.Decode(payload)
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"payload decoding error: ", err.Error()}...))
	}

	hashedPayload, err := m.Hasher.Hash(decodedPayload)
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"hashing error: ", err.Error()}...))
	}

	isValid, err := m.Suite.Verify(hashedPayload, signature)
	if err != nil {
		return false, errors.New(generic.StrCnct([]string{"signature verification error: ", err.Error()}...))
	}
	if !isValid {
		return false, errors.New("invalid signature")
	}
	return true, nil
}

func (m *Minimalistic) Parse(token string) (string, error) {
	if m.Encoder == nil {
		m.Encoder = &generic.Hex{}
	}

	payload, _, err := m.Serialization.Deserializer(token)
	if err != nil {
		return "", errors.New(generic.StrCnct([]string{"deserializer error: ", err.Error()}...))
	}

	decodedPayload, err := m.Encoder.Decode(payload)
	if err != nil {
		return "", errors.New(generic.StrCnct([]string{"payload decoding error: ", err.Error()}...))
	}

	return string(decodedPayload), nil
}

type Serializers interface {
	Serializer(string, string) (string, error)
	Deserializer(string) (string, string, error)
}

type KnownPadding struct {
	Padding int
}

func (k *KnownPadding) Serializer(payload string, signature string) (string, error) {
	if (len(payload) + len(signature)) < k.Padding {
		return "", errors.New("invalid padding, bigger than the data")
	}

	return generic.StrCnct([]string{payload, signature}...), nil
}

func (k *KnownPadding) Deserializer(data string) (string, string, error) {
	if k.Padding == 0 {
		return "", "", errors.New("missing padding declaration")
	}

	if k.Padding > len(data) {
		return "", "", errors.New("invalid padding, bigger than the data")
	}

	return data[:len(data)-k.Padding], data[len(data)-k.Padding:], nil
}

type KnownSeparator struct {
	Separator         string
	PayloadPosition   int
	SignaturePosition int
}

func (k *KnownSeparator) Serializer(payload string, signature string) (string, error) {
	if k.Separator == "" {
		return "", errors.New("missing separator declaration")
	}

	return generic.StrCnct([]string{payload, k.Separator, signature}...), nil
}

func (k *KnownSeparator) Deserializer(data string) (string, string, error) {
	if k.Separator == "" {
		return "", "", errors.New("missing separator declaration")
	}

	positions := strings.Split(data, k.Separator)

	if len(positions) < k.PayloadPosition || len(positions) < k.SignaturePosition {
		return "", "", errors.New("invalid separators position")
	}

	return positions[k.PayloadPosition], positions[k.SignaturePosition], nil
}
