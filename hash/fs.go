package hash

import "github.com/D3vl0per/crypt/generic"

func ReadFileContentAndHash(path string) ([]byte, error) {

	content, err := generic.ReadFileContent(path)
	if err != nil {
		return []byte{}, err
	}
	hash, err := Blake256(content)
	if err != nil {
		return []byte{}, err
	}
	return hash[:], nil
}
