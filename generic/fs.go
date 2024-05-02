package generic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Secure way to delete file.
func Delete(targetPath string, cycle int) error {
	if cycle == 0 {
		cycle = 3
	}
	//nolint:gomnd
	file, err := os.OpenFile(targetPath, os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	zeroBytes := make([]byte, fileInfo.Size())

	for i := 0; i < cycle; i++ {
		// Owerwrite with zeros
		n, err := WriteAndFlush(file, zeroBytes)
		if err != nil {
			return err
		}
		if n != int(fileInfo.Size()) {
			return errors.New("owerwrite bytes mismatch")
		}
		// Owerwrites with random
		rnd, err := CSPRNG(fileInfo.Size())
		if err != nil {
			return err
		}
		n, err = WriteAndFlush(file, rnd)
		if err != nil {
			return err
		}
		if n != int(fileInfo.Size()) {
			return errors.New("rand owerwrite bytes mismatch")
		}
	}

	err = os.Remove(targetPath)
	if err != nil {
		return err
	}
	return nil
}

// Secure way to overwrite file.
func Overwrite(targetPath string, data []byte, cycle int) error {
	if cycle == 0 {
		cycle = 3
	}

	//nolint:gomnd
	file, err := os.OpenFile(targetPath, os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	if len(data) != int(fileInfo.Size()) {
		return errors.New("data size must be equal to file size")
	}

	zeroBytes := make([]byte, fileInfo.Size())

	for i := 0; i < cycle; i++ {
		// Owerwrite with zeros
		n, err := WriteAndFlush(file, zeroBytes)
		if err != nil {
			return err
		}

		if n != int(fileInfo.Size()) {
			return errors.New("owerwrite bytes mismatch")
		}
		// Owerwrites with random
		rnd, err := CSPRNG(fileInfo.Size())
		if err != nil {
			return err
		}

		n, err = WriteAndFlush(file, rnd)
		if err != nil {
			return err
		}
		if n != int(fileInfo.Size()) {
			return errors.New("rand owerwrite bytes mismatch")
		}
	}
	n, err := file.Write(data)
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("file overwrite bytes mismatch")
	}
	return nil
}

func FileWalkByName(startPath, name string) ([]string, error) {
	var paths []string

	err := filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && info.Name() == name {
			paths = append(paths, path)
		}

		return nil
	})
	if err != nil {
		return []string{}, nil
	}
	return paths, nil
}

func ReadFileContent(path string) ([]byte, error) {
	// #do-not-check-gosec
	// read only
	j, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer j.Close()
	data, err := io.ReadAll(j)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func WriteAndFlush(file *os.File, rnd []byte) (n int, err error) {
	n, err = file.Write(rnd)
	if err != nil {
		return 0, err
	}
	err = file.Sync()
	if err != nil {
		return 0, err
	}
	err = file.Truncate(0)
	if err != nil {
		return 0, err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		return 0, err
	}
	return n, nil
}
