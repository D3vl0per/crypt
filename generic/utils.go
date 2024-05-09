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

func IsRepeatingSequence(key []byte) bool {
	for seqLen := 1; seqLen <= len(key)/2; seqLen++ {
		isRepeating := true
		for i := 0; i < len(key)-seqLen; i += seqLen {
			if !bytes.Equal(key[i:i+seqLen], key[i+seqLen:i+2*seqLen]) {
				isRepeating = false
				break
			}
		}

		if isRepeating {
			return true
		}
	}

	return false
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
