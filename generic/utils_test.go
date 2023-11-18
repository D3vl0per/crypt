package generic_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
)

func TestAllZero(t *testing.T) {
	tests := []struct {
		name string
		s    []byte
		want bool
	}{
		{
			name: "Empty slice",
			s:    []byte{},
			want: true,
		},
		{
			name: "All zeros",
			s:    []byte{0, 0, 0, 0},
			want: true,
		},
		{
			name: "Non-zero element",
			s:    []byte{0, 0, 1, 0},
			want: false,
		},
		{
			name: "Mixed elements",
			s:    []byte{0, 0, 0, 1},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generic.AllZero(tt.s); got != tt.want {
				t.Errorf("AllZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestStrCnct(t *testing.T) {
	tests := []struct {
		name string
		str  []string
		want string
	}{
		{
			name: "Empty strings",
			str:  []string{},
			want: "",
		},
		{
			name: "Single string",
			str:  []string{"Hello"},
			want: "Hello",
		},
		{
			name: "Multiple strings",
			str:  []string{"Hello", " ", "World"},
			want: "Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generic.StrCnct(tt.str...); got != tt.want {
				t.Errorf("StrCnct() = %v, want %v", got, tt.want)
			}
		})
	}
}
