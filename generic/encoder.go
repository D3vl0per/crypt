package generic

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
)

type Encoder interface {
	Encode([]byte) string
	Decode(string) ([]byte, error)
	GetName() string
}

// StdEncoding is the standard base64 encoding, as defined in RFC 4648.
type Base64 struct{}

// URLEncoding is the alternate base64 encoding defined in RFC 4648. It is typically used in URLs and file names.
type URLBase64 struct{}

// nolint: lll
// RawURLEncoding is the unpadded alternate base64 encoding defined in RFC 4648. It is typically used in URLs and file names. This is the same as URLEncoding but omits padding characters.
type RawURLBase64 struct{}

// nolint: lll
// RawStdEncoding is the standard raw, unpadded base64 encoding, as defined in RFC 4648 section 3.2. This is the same as StdEncoding but omits padding characters.
type RawBase64 struct{}

type Base32 struct{}

type PaddinglessBase32 struct{}

type Hex struct{}

///
/// Base64
///

func (b *Base64) Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (b *Base64) Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func (b *Base64) GetName() string {
	return "base64"
}

///
/// URLBase64
///

func (b *URLBase64) Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func (b *URLBase64) Decode(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}

func (b *URLBase64) GetName() string {
	return "urlbase64"
}

///
/// RawURLBase64
//

func (b *RawURLBase64) Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func (b *RawURLBase64) Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

func (b *RawURLBase64) GetName() string {
	return "rawurlbase64"
}

///
/// RawBase64
///

func (b *RawBase64) Encode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

func (b *RawBase64) Decode(data string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(data)
}

func (b *RawBase64) GetName() string {
	return "rawbase64"
}

///
/// Base32
///

func (b *Base32) Encode(data []byte) string {
	return base32.StdEncoding.EncodeToString(data)
}

func (b *Base32) Decode(data string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(data)
}

func (b *Base32) GetName() string {
	return "base32"
}

///
/// PaddinglessBase32
///

func (b *PaddinglessBase32) Encode(data []byte) string {
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoder.EncodeToString(data)
}

func (b *PaddinglessBase32) Decode(data string) ([]byte, error) {
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoder.DecodeString(data)
}

func (b *PaddinglessBase32) GetName() string {
	return "paddinglessbase32"
}

///
/// Hex
///

func (h *Hex) Encode(data []byte) string {
	return hex.EncodeToString(data)
}

func (h *Hex) Decode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

func (h *Hex) GetName() string {
	return "hex"
}
