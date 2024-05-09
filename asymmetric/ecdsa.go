package asymmetric

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"

	"github.com/D3vl0per/crypt/generic"
	"github.com/cloudflare/circl/sign/ed448"
)

var testSignData = []byte("shibboleet")
var ErrTestSigning = errors.New("test signing failed, incorrect private key")
var ErrPublicKeyAssert = errors.New("public key type assertion error")
var ErrSecretKeyAssert = errors.New("secret key type assertion error")
var ErrInvalidPublicKeySize = errors.New("invalid public key size")
var ErrInvalidSecretKeySize = errors.New("invalid secret key size")

///
/// Ed25519 Suite
///

type Signing interface {
	Generate() error
	GenerateFromSeed([]byte) error
	Sign([]byte) string
	Verify([]byte, string) (bool, error)
	GetSecretKey() []byte
	GetSecretKeyString() string
	GetPublicKey() []byte
	GetPublicKeyString() string
	GetEncoder() generic.Encoder
	SetEncoder(generic.Encoder)
	CryptoToPublicKey(crypto.PublicKey) error
	CryptoToSecretKey(crypto.PrivateKey) error
	StringToPublicKey(string) error
	StringToSecretKey(string) error
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
	e.PublicKey, e.SecretKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (e *Ed25519) GenerateFromSeed(seed []byte) error {
	if l := len(seed); l != ed25519.SeedSize {
		return errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed25519.SeedSize), " bytes long"}...))
	}
	e.SecretKey = ed25519.NewKeyFromSeed(seed)
	return e.CryptoToPublicKey(e.SecretKey.Public())
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
	}
	sigRaw, err := e.Encoder.Decode(sig)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(e.PublicKey, msg, sigRaw), nil

}

func (e *Ed25519) GetSecretKey() []byte {
	return e.SecretKey
}

func (e *Ed25519) GetSecretKeyString() string {
	if e.Encoder == nil {
		return string(e.SecretKey)
	}

	return e.Encoder.Encode(e.SecretKey)
}

func (e *Ed25519) GetPublicKey() []byte {
	return e.PublicKey
}

func (e *Ed25519) GetPublicKeyString() string {
	if e.Encoder == nil {
		return string(e.PublicKey)
	}

	return e.Encoder.Encode(e.PublicKey)
}

func (e *Ed25519) GetEncoder() generic.Encoder {
	return e.Encoder
}

func (e *Ed25519) SetEncoder(encoder generic.Encoder) {
	e.Encoder = encoder
}

func (e *Ed25519) CryptoToPublicKey(pub crypto.PublicKey) error {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		e.PublicKey = pub
		return nil
	default:
		return ErrPublicKeyAssert
	}
}

func (e *Ed25519) CryptoToSecretKey(sec crypto.PrivateKey) error {
	switch sec := sec.(type) {
	case ed25519.PrivateKey:
		e.SecretKey = sec
		return nil
	default:
		return ErrSecretKeyAssert
	}
}

func (e *Ed25519) StringToPublicKey(public string) (err error) {
	var pubRaw []byte
	if e.Encoder != nil {
		pubRaw, err = e.Encoder.Decode(public)
		if err != nil {
			return err
		}
	} else {
		pubRaw = []byte(public)
	}

	if len(pubRaw) != ed25519.PublicKeySize {
		return ErrInvalidPublicKeySize
	}

	e.PublicKey = ed25519.PublicKey(pubRaw)

	return nil
}

func (e *Ed25519) StringToSecretKey(secret string) (err error) {
	var secRaw []byte
	if e.Encoder != nil {
		secRaw, err = e.Encoder.Decode(secret)
		if err != nil {
			return err
		}
	} else {
		secRaw = []byte(secret)
	}

	if len(secRaw) != ed25519.PrivateKeySize {
		return ErrInvalidSecretKeySize
	}

	e.SecretKey = ed25519.PrivateKey(secRaw)

	pub, ok := e.SecretKey.Public().(ed25519.PublicKey)
	if !ok {
		return ErrPublicKeyAssert
	}
	e.PublicKey = pub

	sig := ed25519.Sign(e.SecretKey, testSignData)
	valid := ed25519.Verify(e.PublicKey, testSignData, sig)
	if !valid {
		return ErrTestSigning
	}
	return nil
}

///
/// ED448 Suite
///

func (e *Ed448) Generate() error {
	var err error
	e.PublicKey, e.SecretKey, err = ed448.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return nil
}

func (e *Ed448) GenerateFromSeed(seed []byte) error {
	if l := len(seed); l != ed448.SeedSize {
		return errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed448.SeedSize), " bytes long"}...))
	}

	e.SecretKey = ed448.NewKeyFromSeed(seed)
	return e.CryptoToPublicKey(e.SecretKey.Public())
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
	}
	sigRaw, err := e.Encoder.Decode(sig)
	if err != nil {
		return false, err
	}
	return ed448.Verify(e.PublicKey, msg, sigRaw, e.Context), nil
}

func (e *Ed448) GetSecretKey() []byte {
	return e.SecretKey
}

func (e *Ed448) GetPublicKey() []byte {
	return e.PublicKey
}

func (e *Ed448) GetPublicKeyString() string {
	if e.Encoder == nil {
		return string(e.PublicKey)
	}

	return e.Encoder.Encode(e.PublicKey)
}

func (e *Ed448) GetSecretKeyString() string {
	if e.Encoder == nil {
		return string(e.SecretKey)
	}

	return e.Encoder.Encode(e.SecretKey)
}

func (e *Ed448) GetEncoder() generic.Encoder {
	return e.Encoder
}

func (e *Ed448) SetEncoder(encoder generic.Encoder) {
	e.Encoder = encoder
}

func (e *Ed448) CryptoToPublicKey(pub crypto.PublicKey) error {
	switch pub := pub.(type) {
	case ed448.PublicKey:
		e.PublicKey = pub
		return nil
	default:
		return ErrPublicKeyAssert
	}
}

func (e *Ed448) CryptoToSecretKey(sec crypto.PrivateKey) error {
	switch sec := sec.(type) {
	case ed448.PrivateKey:
		e.SecretKey = sec
		return nil
	default:
		return ErrSecretKeyAssert
	}
}

func (e *Ed448) StringToPublicKey(public string) (err error) {
	var pubRaw []byte
	if e.Encoder != nil {
		pubRaw, err = e.Encoder.Decode(public)
		if err != nil {
			return err
		}
	} else {
		pubRaw = []byte(public)
	}

	if len(pubRaw) != ed448.PublicKeySize {
		return ErrInvalidPublicKeySize
	}

	e.PublicKey = ed448.PublicKey(pubRaw)

	return nil
}

func (e *Ed448) StringToSecretKey(secret string) (err error) {
	var secRaw []byte
	if e.Encoder != nil {
		secRaw, err = e.Encoder.Decode(secret)
		if err != nil {
			return err
		}
	} else {
		secRaw = []byte(secret)
	}

	if len(secRaw) != ed448.PrivateKeySize {
		return ErrInvalidSecretKeySize
	}

	e.SecretKey = ed448.PrivateKey(secRaw)

	pub, ok := e.SecretKey.Public().(ed448.PublicKey)
	if !ok {
		return ErrPublicKeyAssert
	}
	e.PublicKey = pub

	sig := ed448.Sign(e.SecretKey, testSignData, e.Context)
	valid := ed448.Verify(e.PublicKey, testSignData, sig, e.Context)
	if !valid {
		return ErrTestSigning
	}
	return nil
}
