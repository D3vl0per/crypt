package crypt

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/D3vl0per/crypt/generic"
	"github.com/cloudflare/circl/sign/ed448"
)

///
/// Ed25519 Suite
///

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pk, sk, err := ed25519.GenerateKey(generic.Rand())
	if err != nil {
		return ed25519.PublicKey{}, ed25519.PrivateKey{}, err
	}
	return pk, sk, err
}

func GenerateEd25519KeypairFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if l := len(seed); l != ed25519.SeedSize {
		return nil, errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed25519.SeedSize), " bytes long"}...))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func SignEd25519(sk ed25519.PrivateKey, msg []byte) string {
	return hex.EncodeToString(ed25519.Sign(sk, msg))
}

func VerifyEd25519(pk ed25519.PublicKey, msg []byte, sig string) (bool, error) {
	sig_raw, err := hex.DecodeString(sig)
	if err != nil {
		return false, err
	}

	return ed25519.Verify(pk, msg, sig_raw), nil
}

///
/// ED448 Suite
///

func GenerateEd448Keypair() (ed448.PublicKey, ed448.PrivateKey, error) {
	pk, sk, err := ed448.GenerateKey(generic.Rand())
	if err != nil {
		return ed448.PublicKey{}, ed448.PrivateKey{}, err
	}
	return pk, sk, err
}

func GenerateEd448KeypairFromSeed(seed []byte) (ed448.PrivateKey, error) {
	if l := len(seed); l != ed448.SeedSize {
		return nil, errors.New(generic.StrCnct([]string{"seed size must be ", strconv.Itoa(ed448.SeedSize), " bytes long"}...))
	}
	return ed448.NewKeyFromSeed(seed), nil
}

func SignEd448(sk ed25519.PrivateKey, msg []byte) string {
	return hex.EncodeToString(ed25519.Sign(sk, msg))
}

func VerifyEd448(pk ed448.PublicKey, msg []byte, sig string) (bool, error) {
	sig_raw, err := hex.DecodeString(sig)
	if err != nil {
		return false, err
	}

	return ed448.Verify(pk, msg, sig_raw, ""), nil
}
