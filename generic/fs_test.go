package generic_test

import (
	"os"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestReadFileContent(t *testing.T) {
	tempFile, err := os.CreateTemp("", "readfilecontent.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	expectedData, err := generic.CSPRNG(256)
	r.NoError(t, err)

	_, err = tempFile.Write(expectedData)
	r.NoError(t, err)

	data, err := generic.ReadFileContent(tempFile.Name())
	r.NoError(t, err)
	r.Equal(t, expectedData, data)
}
