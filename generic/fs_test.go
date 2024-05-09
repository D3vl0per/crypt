package generic_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestWriteAndFlush(t *testing.T) {
	tempFile, err := os.CreateTemp("", "writeandflush.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	notExpectedData, err := generic.CSPRNG(256)
	r.NoError(t, err)

	_, err = tempFile.Write(notExpectedData)
	r.NoError(t, err)

	err = tempFile.Sync()
	r.NoError(t, err)
	err = tempFile.Close()
	r.NoError(t, err)

	expectedData, err := generic.CSPRNG(256)
	r.NoError(t, err)

	overwriteFile, err := os.Create(tempFile.Name())
	r.NoError(t, err)

	n, err := generic.WriteAndFlush(overwriteFile, expectedData)
	r.NoError(t, err)

	r.Equal(t, len(expectedData), n)

	overwrite, err := generic.ReadFileContent(tempFile.Name())
	r.NoError(t, err)

	r.NotEqual(t, notExpectedData, overwrite)
}

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

func TestFileWalkByName(t *testing.T) {
	startPath := "/tmp"
	name := "file.txt"

	// Create temporary test files
	tempFiles := []string{
		filepath.Join(startPath, "file.txt"),
		filepath.Join(startPath, "subdir1", "file.txt"),
		filepath.Join(startPath, "subdir2", "file.txt"),
		filepath.Join(startPath, "subdir2", "file2.txt"),
	}
	for _, tempFile := range tempFiles {
		err := os.MkdirAll(filepath.Dir(tempFile), os.ModePerm)
		r.NoError(t, err)

		file, err := os.Create(tempFile)
		r.NoError(t, err)
		file.Close()
	}

	// Clean up temporary test files
	defer func() {
		for _, tempFile := range tempFiles {
			err := os.RemoveAll(tempFile)
			r.NoError(t, err)
		}
	}()

	expectedPaths := []string{
		filepath.Join(startPath, "file.txt"),
		filepath.Join(startPath, "subdir1", "file.txt"),
		filepath.Join(startPath, "subdir2", "file.txt"),
	}

	paths, err := generic.FileWalkByName(startPath, name)
	r.NoError(t, err)
	r.ElementsMatch(t, expectedPaths, paths)
}

func TestDelete(t *testing.T) {
	tempFile, err := os.CreateTemp("", "delete_test.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	data, err := generic.CSPRNG(256)
	r.NoError(t, err)

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	err = tempFile.Close()
	r.NoError(t, err)

	err = generic.Delete(tempFile.Name(), 3)
	r.NoError(t, err)

	_, err = os.Stat(tempFile.Name())
	r.True(t, os.IsNotExist(err))
}

func TestOverwrite(t *testing.T) {
	tempFile, err := os.CreateTemp("", "delete_test.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	data, err := generic.CSPRNG(256)
	r.NoError(t, err)

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	cycle := 3

	err = generic.Overwrite(tempFile.Name(), data, cycle)
	r.NoError(t, err)

	file, err := os.Open(tempFile.Name())
	r.NoError(t, err)
	defer file.Close()

	fileInfo, err := file.Stat()
	r.NoError(t, err)

	readData := make([]byte, fileInfo.Size())
	_, err = file.Read(readData)
	r.NoError(t, err)

	r.Equal(t, data, readData)
}
