package generic_test

import (
	"errors"
	"os"
	"testing"

	"github.com/D3vl0per/crypt/generic"
)

func TestDelete(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	// Write some data to the temporary file
	data := []byte("test data")
	_, err = tempFile.Write(data)
	if err != nil {
		t.Fatal(err)
	}

	// Close the file before deleting it
	err = tempFile.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Call the Delete function with the temporary file path
	err = generic.Delete(tempFile.Name(), 3)
	if err != nil {
		t.Fatal(err)
	}

	// Check if the file has been deleted
	_, err = os.Stat(tempFile.Name())
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected file to be deleted, got error: %v", err)
	}
}

/*
func TestOverwrite(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	// Write some data to the temporary file
	data := []byte("test data")
	_, err = tempFile.Write(data)
	if err != nil {
		t.Fatal(err)
	}

	// Close the file before overwriting it
	err = tempFile.Close()
	if err != nil {
		t.Fatal(err)
	}

	expectedContents := []byte("new data")
	// Call the Overwrite function with the temporary file path
	err = generic.Overwrite(tempFile.Name(), expectedContents, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Read the contents of the file
	fileContents, err := generic.ReadFileContent(tempFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(fileContents))

	// Check if the file has been overwritten correctly
	if !bytes.Equal(fileContents, expectedContents) {
		t.Errorf("expected file contents to be %q, got %q", expectedContents, fileContents)
	}
}
*/
