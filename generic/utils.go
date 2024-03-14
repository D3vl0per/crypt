package generic

import (
	"bytes"
)

// AllZero checks if all bytes in a slice are zero.
func AllZero(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

// StrCnct concatenates strings into one
// Example: StrCnct([]string{"a", "b", "c"}...) -> "abc".
func StrCnct(str ...string) string {
	var buffer bytes.Buffer

	for _, e := range str {
		buffer.WriteString(e)
	}

	return buffer.String()
}
