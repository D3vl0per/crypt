package generic_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestE2EEncode(t *testing.T){
	data := []byte("I'd just like to interject for a moment.")
	tests := []struct {
		name string
		encoder generic.Encoder
	}{
		{
			name: "base64",
			encoder: &generic.Base64{},
		},
		{
			name: "urlbase64",
			encoder: &generic.URLBase64{},
		},
		{
			name: "rawurlbase64",
			encoder: &generic.RawURLBase64{},
		},
		{
			name: "rawbase64",
			encoder: &generic.RawBase64{},
		},
		{
			name: "base32",
			encoder: &generic.Base32{},
		},
		{
			name: "paddinglessbase32",
			encoder: &generic.PaddinglessBase32{},
		},
		{
			name: "hex",
			encoder: &generic.Hex{},
		},
		{
			name: "custom",
			encoder: &generic.Custom{
				Encoder: func(data []byte) string {
					return string(data)
				},
				Decoder: func(data string) ([]byte, error) {
					return []byte(data), nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r.Equal(t, tt.name, tt.encoder.GetName())

			encoded := tt.encoder.Encode(data)
			decoded, err := tt.encoder.Decode(encoded)
			r.NoError(t, err)
			r.Equal(t, data, decoded)
		})
	}
}