package asymmetric

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"strconv"

	"github.com/D3vl0per/crypt/generic"
	"github.com/cloudflare/circl/sign/ed448"
)

///
/// Ed25519 Suite
///

type Signing interface {
	Generate() error
	GenerateFromSeed([]byte) error
	Sign([]byte) string
	Verify([]byte, string) (bool, error)
	GetSecretKey() []byte
	GetPublicKey() []byte
	GetEncoder() generic.Encoder
}

type Ed25519 struct {
	SecretKey ed25519.PrivateKey
	PublicKey ed25519.PublicKey
	Encoder   generic.Encoder
}
type Ed448 struct {
	SecretKey ed448.PrivateKey
	PublicKey ed448.PublicKey
	Context   string
	Encoder   generic.Encoder
}

func (e *Ed25519) Generate() error {
	var err error
	e.PublicKey, e.SecretKey, err = ed25519.GenerateKey(generic.Rand())
	if err != nil {
		return err
	}

	return nil
}

func (e *Ed25519) GenerateFromSeed(seed []byte) error {
	if l := len(seed); l != ed25519.SeedSize {
		return errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed25519.SeedSize), " bytes long"}...))
	}
	var err error
	e.SecretKey = ed25519.NewKeyFromSeed(seed)
	e.PublicKey, err = Ed25519ToPublicKey(e.SecretKey.Public())
	return err
}

func (e *Ed25519) Sign(msg []byte) string {
	if e.Encoder == nil {
		return string(ed25519.Sign(e.SecretKey, msg))
	}

	return e.Encoder.Encode(ed25519.Sign(e.SecretKey, msg))
}

func (e *Ed25519) Verify(msg []byte, sig string) (bool, error) {

	if e.Encoder == nil {
		return ed25519.Verify(e.PublicKey, msg, []byte(sig)), nil
	} else {
		sig_raw, err := e.Encoder.Decode(sig)
		if err != nil {
			return false, err
		}
		return ed25519.Verify(e.PublicKey, msg, sig_raw), nil
	}
}

func (e *Ed25519) GetSecretKey() []byte {
	return e.SecretKey
}

func (e *Ed25519) GetPublicKey() []byte {
	return e.PublicKey
}

func (e *Ed25519) GetEncoder() generic.Encoder {
	return e.Encoder
}

///
/// ED448 Suite
///

func (e *Ed448) Generate() error {
	var err error
	e.PublicKey, e.SecretKey, err = ed448.GenerateKey(generic.Rand())
	if err != nil {
		return err
	}
	return nil
}

func (e *Ed448) GenerateFromSeed(seed []byte) error {
	if l := len(seed); l != ed448.SeedSize {
		return errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed448.SeedSize), " bytes long"}...))
	}
	var err error
	e.SecretKey = ed448.NewKeyFromSeed(seed)
	e.PublicKey, err = Ed448ToPublicKey(e.SecretKey.Public())
	return err
}

func (e *Ed448) Sign(msg []byte) string {
	if e.Encoder == nil {
		return string(ed448.Sign(e.SecretKey, msg, e.Context))
	}

	return string(e.Encoder.Encode(ed448.Sign(e.SecretKey, msg, e.Context)))
}

func (e *Ed448) Verify(msg []byte, sig string) (bool, error) {
	if e.Encoder == nil {
		return ed448.Verify(e.PublicKey, msg, []byte(sig), e.Context), nil
	} else {
		sig_raw, err := e.Encoder.Decode(sig)
		if err != nil {
			return false, err
		}
		return ed448.Verify(e.PublicKey, msg, sig_raw, e.Context), nil
	}
}

func (e *Ed448) GetSecretKey() []byte {
	return e.SecretKey
}

func (e *Ed448) GetPublicKey() []byte {
	return e.PublicKey
}

func (e *Ed448) GetEncoder() generic.Encoder {
	return e.Encoder
}

func Ed25519ToPublicKey(pub crypto.PublicKey) (ed25519.PublicKey, error) {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("public key type")
	}
}

func Ed448ToPublicKey(pub crypto.PublicKey) (ed448.PublicKey, error) {
	switch pub := pub.(type) {
	case ed448.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("public key type")
	}
}
