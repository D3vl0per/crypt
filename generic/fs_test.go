package generic_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestDelete(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "testfile")
	r.NoError(t, err)

	defer os.Remove(tempFile.Name())

	// Write some data to the temporary file
	data := []byte("test data")
	_, err = tempFile.Write(data)
	r.NoError(t, err)

	// Close the file before deleting it
	err = tempFile.Close()
	r.NoError(t, err)

	// Call the Delete function with the temporary file path
	err = generic.Delete(tempFile.Name(), 3)
	r.NoError(t, err)

	// Check if the file has been deleted
	_, err = os.Stat(tempFile.Name())
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected file to be deleted, got error: %v", err)
	}
}
func TestOverwrite(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "testfile")
	r.NoError(t, err)

	defer os.Remove(tempFile.Name())

	// Write some data to the temporary file
	data, err := generic.CSPRNG(32)
	r.NoError(t, err)

	expectedContents, err := generic.CSPRNG(32)
	r.NoError(t, err)

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	// Close the file before overwriting it
	err = tempFile.Close()
	r.NoError(t, err)

	// Call the Overwrite function with the temporary file path
	err = generic.Overwrite(tempFile.Name(), expectedContents, 10)
	r.NoError(t, err)

	// Read the contents of the file
	fileContents, err := generic.ReadFileContent(tempFile.Name())
	r.NoError(t, err)

	// Check if the file contents have been overwritten
	if !bytes.Equal(fileContents, expectedContents) {
		t.Errorf("expected file contents to be %q, got %q", expectedContents, fileContents)
	}
}
