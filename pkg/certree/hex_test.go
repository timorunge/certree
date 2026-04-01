package certree

import (
	"testing"
)

func TestColonHex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"short", "AB", "AB"},
		{"two pairs", "ABCD", "AB:CD"},
		{"four pairs", "A887602F", "A8:87:60:2F"},
		{"odd length", "ABC", "AB:C"},
		{"empty", "", ""},
		{"single char", "A", "A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ColonHex(tt.input); got != tt.want {
				t.Errorf("ColonHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestStripColons(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with colons", "A8:87:60:2F", "A887602F"},
		{"no colons", "A887602F", "A887602F"},
		{"empty", "", ""},
		{"only colons", ":::", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stripColons(tt.input); got != tt.want {
				t.Errorf("stripColons(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
