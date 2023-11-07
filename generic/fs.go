package generic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func SecureDelete(targetPath string, cycle int) error {
	if cycle == 0 {
		cycle = 3
	}
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
	copy(zeroBytes, "0")

	for i := 0; i < cycle; i++ {
		// Owerwrite with zeros
		n, err := file.Write([]byte(zeroBytes))
		if err != nil {
			return err
		}
		err = file.Sync()
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
		err = file.Sync()
		if err != nil {
			return err
		}
		n, err = file.Write(rnd)
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

func SecureOverwrite(targetPath string, data []byte, cycle int) error {
	if cycle == 0 {
		cycle = 3
	}

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
	copy(zeroBytes, "0")

	for i := 0; i < cycle; i++ {
		// Owerwrite with zeros
		n, err := file.Write([]byte(zeroBytes))
		if err != nil {
			return err
		}
		err = file.Sync()
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

		n, err = file.Write(rnd)
		if err != nil {
			return err
		}
		err = file.Sync()
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
	if n != int(fileInfo.Size()) {
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
	j, err := os.Open(path)
	if err != nil {
		return []byte{}, err
	}
	defer j.Close()
	data, err := io.ReadAll(j)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}
