package hash

import "github.com/D3vl0per/crypt/generic"

func ReadFileContentAndHash(algo Algorithms, path string) ([]byte, error) {
	content, err := generic.ReadFileContent(path)
	if err != nil {
		return []byte{}, err
	}
	hash, err := algo.Hash(content)
	if err != nil {
		return []byte{}, err
	}
	return hash, nil
}
