package aged

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/age"
	"github.com/D3vl0per/crypt/compression"
)

type Keychain struct {
	secretKey  *age.X25519Identity
	recipients []age.Recipient
}

func SetupKeychain(secretKey string, publicKeys []string) (Keychain, error) {
	var keychain Keychain

	identity, err := age.ParseX25519Identity(secretKey)
	if err != nil {
		return Keychain{}, err
	}
	keychain.secretKey = identity
	keychain.recipients = append(keychain.recipients, identity.Recipient())

	for _, e := range publicKeys {
		publicKey, err := age.ParseX25519Recipient(e)
		if err != nil {
			return Keychain{}, err
		}
		keychain.recipients = append(keychain.recipients, publicKey)
	}

	return keychain, nil
}

func GenKeypair() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return identity, err
	}
	return identity, nil
}

func (k Keychain) Encrypt(data []byte, compress bool, header bool) ([]byte, error) {
	var reader *bytes.Reader
	if compress {
		raw, err := compression.GzipCompress(data, 6)
		if err != nil {
			return []byte{}, err
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(data)
	}

	out := &bytes.Buffer{}
	w, err := age.Encrypt(out, k.recipients...)
	if err != nil {
		return []byte{}, err
	}

	if err != nil {
		return []byte{}, err
	}

	if _, err := io.Copy(w, reader); err != nil {
		return []byte{}, err
	}
	if err := w.Close(); err != nil {
		return []byte{}, err
	}

	if header {
		obf, err := ObfHeader(out.Bytes())
		if err != nil {
			return []byte{}, errors.New("failed to obfuscate header")
		}
		return obf, nil
	}
	return out.Bytes(), nil
}

func (k Keychain) Decrypt(cipherdata []byte, compress bool, header bool) ([]byte, error) {
	if header {
		var err error
		cipherdata, err = DeobfHeader(cipherdata)
		if err != nil {
			return []byte{}, errors.New("failed to deobfuscate header, maybe not encrypted")
		}
	}

	r, err := age.Decrypt(bytes.NewReader(cipherdata), k.secretKey)
	if err != nil {
		return []byte{}, err
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return []byte{}, err
	}

	if compress {
		raw, err := compression.GzipDecompress(out.Bytes())
		if err != nil {
			return []byte{}, err
		}
		return raw, nil
	}

	return out.Bytes(), nil
}

func EncryptWithPwd(pwd string, data []byte, compress bool, header bool) ([]byte, error) {
	var reader *bytes.Reader
	if compress {
		raw, err := compression.GzipCompress(data, 6)
		if err != nil {
			return []byte{}, err
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(data)
	}

	pwdRecepient, err := age.NewScryptRecipient(pwd)
	if err != nil {
		return []byte{}, err
	}

	out := &bytes.Buffer{}
	w, err := age.Encrypt(out, pwdRecepient)
	if err != nil {
		return []byte{}, err
	}

	if err != nil {
		return []byte{}, err
	}

	if _, err := io.Copy(w, reader); err != nil {
		return []byte{}, err
	}
	if err := w.Close(); err != nil {
		return []byte{}, err
	}

	if header {
		obf, err := ObfHeader(out.Bytes())
		if err != nil {
			return []byte{}, errors.New("failed to obfuscate header")
		}
		return obf, nil
	}
	return out.Bytes(), nil
}

func DecryptWithPwd(pwd string, cipherdata []byte, compress bool, header bool) ([]byte, error) {
	if header {
		var err error
		cipherdata, err = DeobfHeader(cipherdata)
		if err != nil {
			return []byte{}, errors.New("failed to deobfuscate header, maybe not encrypted")
		}
	}

	pwdIdentity, err := age.NewScryptIdentity(pwd)
	if err != nil {
		return []byte{}, err
	}

	r, err := age.Decrypt(bytes.NewReader(cipherdata), pwdIdentity)
	if err != nil {
		return []byte{}, err
	}

	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return []byte{}, err
	}

	if compress {
		raw, err := compression.GzipDecompress(out.Bytes())
		if err != nil {
			return []byte{}, err
		}
		return raw, nil
	}

	return out.Bytes(), nil
}
