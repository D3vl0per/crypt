package generic

import "crypto/subtle"

func Compare(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

func CompareString(x, y string) bool {
	return Compare([]byte(x), []byte(y))
}
