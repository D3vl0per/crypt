package aged

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/D3vl0per/crypt/compression"
)

type Keychain struct {
	secretKey  *age.X25519Identity
	recipients []age.Recipient
}

type SetupKeychainParameters struct {
	SecretKey     string
	PublicKeys    []string
	SelfRecipient bool
}

func SetupKeychain(keychainSetup SetupKeychainParameters) (Keychain, error) {
	var keychain Keychain

	identity, err := age.ParseX25519Identity(keychainSetup.SecretKey)
	if err != nil {
		return Keychain{}, err
	}

	keychain.secretKey = identity

	for _, e := range keychainSetup.PublicKeys {
		if e == "" {
			continue
		}
		if identity.Recipient().String() != e {
			publicKey, err := age.ParseX25519Recipient(e)
			if err != nil {
				return Keychain{}, err
			}
			keychain.recipients = append(keychain.recipients, publicKey)
		}
	}

	if keychainSetup.SelfRecipient {
		keychain.recipients = append(keychain.recipients, identity.Recipient())
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

type Parameters struct {
	Data        []byte
	Compressor  compression.Compressor
	Compress    bool
	Obfuscation bool
	Obfuscator  Obfuscation
}

func (k Keychain) Encrypt(p Parameters) ([]byte, error) {

	in, err := compressor(p)
	if err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	w, err := age.Encrypt(out, k.recipients...)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(w, in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return obfuscator(p, out.Bytes())
}

func (k Keychain) Decrypt(p Parameters) ([]byte, error) {
	cipherData, err := deobfuscator(p)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(cipherData), k.secretKey)
	if err != nil {
		return nil, err
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return nil, err
	}

	return decompressor(p, out.Bytes())
}

func EncryptWithPwd(p Parameters, pwd string) ([]byte, error) {
	in, err := compressor(p)
	if err != nil {
		return nil, err
	}

	pwdRecepient, err := age.NewScryptRecipient(pwd)
	if err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	w, err := age.Encrypt(out, pwdRecepient)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(w, in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return obfuscator(p, out.Bytes())
}

func DecryptWithPwd(p Parameters, pwd string) ([]byte, error) {
	cipherData, err := deobfuscator(p)
	if err != nil {
		return nil, err
	}

	pwdIdentity, err := age.NewScryptIdentity(pwd)
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(cipherData), pwdIdentity)
	if err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return nil, err
	}

	return decompressor(p, out.Bytes())
}

func compressor(p Parameters) (*bytes.Reader, error) {
	var in *bytes.Reader

	if p.Compress {
		var writer bytes.Buffer
		compressorIn := bytes.NewReader(p.Data)

		err := p.Compressor.CompressStream(compressorIn, &writer)
		if err != nil {
			return nil, err
		}

		in = bytes.NewReader(writer.Bytes())

	} else {
		in = bytes.NewReader(p.Data)
	}
	return in, nil
}

func decompressor(p Parameters, data []byte) ([]byte, error) {
	if p.Compress {
		raw, err := p.Compressor.Decompress(data)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	return data, nil
}

func obfuscator(p Parameters, in []byte) ([]byte, error) {
	if p.Obfuscation {
		obf, err := p.Obfuscator.Obfuscate(in)
		if err != nil {
			return nil, errors.New("failed to obfuscate header")
		}
		return obf, nil
	}
	return in, nil
}

func deobfuscator(p Parameters) ([]byte, error) {
	var cipherData []byte
	if p.Obfuscation {
		var err error
		cipherData, err = p.Obfuscator.Deobfuscate(p.Data)
		if err != nil {
			return nil, errors.New("failed to deobfuscate header, maybe not obfuscated?")
		}
	} else {
		cipherData = p.Data
	}
	return cipherData, nil
}

func (k Keychain) KeychainExport() []string {
	keys := make([]string, len(k.recipients))
	for _, key := range k.recipients {
		keys = append(keys, fmt.Sprint(key))
	}
	return keys
}

func (k Keychain) KeychainExportSecretKey() string {
	return k.secretKey.String()
}
