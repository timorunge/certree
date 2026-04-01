package certree

import "testing"

func TestPatternMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		value    string
		want     bool
	}{
		{name: "exact match", patterns: []string{"Root CA"}, value: "Root CA", want: true},
		{name: "no match", patterns: []string{"Root CA"}, value: "Other CA", want: false},
		{name: "wildcard prefix", patterns: []string{"Root*"}, value: "Root CA", want: true},
		{name: "wildcard suffix", patterns: []string{"*CA"}, value: "Root CA", want: true},
		{name: "wildcard middle", patterns: []string{"Root*CA"}, value: "Root Intermediate CA", want: true},
		{name: "question mark", patterns: []string{"Root C?"}, value: "Root CA", want: true},
		{name: "question mark no match", patterns: []string{"Root C?"}, value: "Root CAx", want: false},
		{name: "multiple patterns first matches", patterns: []string{"Root*", "Other*"}, value: "Root CA", want: true},
		{name: "multiple patterns second matches", patterns: []string{"Other*", "Root*"}, value: "Root CA", want: true},
		{name: "multiple patterns none match", patterns: []string{"Foo*", "Bar*"}, value: "Root CA", want: false},
		{name: "empty patterns", patterns: []string{}, value: "Root CA", want: false},
		{name: "nil patterns", patterns: nil, value: "Root CA", want: false},
		{name: "empty pattern matches nothing", patterns: []string{""}, value: "", want: false},
		{name: "star matches anything", patterns: []string{"*"}, value: "Root CA", want: true},
		{name: "invalid pattern ignored", patterns: []string{"[invalid"}, value: "anything", want: false},
		{name: "exact match preferred over glob", patterns: []string{"Root CA"}, value: "Root CA", want: true},
		{name: "character class", patterns: []string{"Root [CI]A"}, value: "Root CA", want: true},
		{name: "pipe OR first matches", patterns: []string{"Root CA|Other CA"}, value: "Root CA", want: true},
		{name: "pipe OR second matches", patterns: []string{"Other CA|Root CA"}, value: "Root CA", want: true},
		{name: "pipe OR none match", patterns: []string{"Foo|Bar"}, value: "Root CA", want: false},
		{name: "pipe OR with wildcards", patterns: []string{"Foo*|Root*"}, value: "Root CA", want: true},
		{name: "pipe OR trims whitespace", patterns: []string{"Foo | Root CA"}, value: "Root CA", want: true},
		{name: "pipe OR empty alternatives ignored", patterns: []string{"|Root CA|"}, value: "Root CA", want: true},
		{name: "colon-separated hex stripped", patterns: []string{"A8:87:60:2F"}, value: "A887602F", want: true},
		{name: "colon hex wildcard", patterns: []string{"A8:87:*"}, value: "A887602F", want: true},
		{name: "colon-free hex still matches", patterns: []string{"A887602F"}, value: "A887602F", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewPatternMatcher(tt.patterns)
			got := m.Match(tt.value)
			if got != tt.want {
				t.Errorf("PatternMatcher(%v).Match(%q) = %v, want %v", tt.patterns, tt.value, got, tt.want)
			}
		})
	}
}

func TestPatternMatcher_NilReceiver(t *testing.T) {
	t.Parallel()

	var m *PatternMatcher
	if m.Match("anything") {
		t.Error("nil PatternMatcher.Match() should return false")
	}
	if m.MatchAny([]string{"a", "b"}) {
		t.Error("nil PatternMatcher.MatchAny() should return false")
	}
}

func TestPatternMatcher_MatchAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		values   []string
		want     bool
	}{
		{name: "one value matches", patterns: []string{"foo"}, values: []string{"bar", "foo"}, want: true},
		{name: "no values match", patterns: []string{"foo"}, values: []string{"bar", "baz"}, want: false},
		{name: "empty values", patterns: []string{"foo"}, values: []string{}, want: false},
		{name: "nil values", patterns: []string{"foo"}, values: nil, want: false},
		{name: "wildcard matches one", patterns: []string{"*.com"}, values: []string{"example.org", "example.com"}, want: true},
		{name: "empty patterns matches nothing", patterns: []string{}, values: []string{"foo"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewPatternMatcher(tt.patterns)
			got := m.MatchAny(tt.values)
			if got != tt.want {
				t.Errorf("PatternMatcher(%v).MatchAny(%v) = %v, want %v", tt.patterns, tt.values, got, tt.want)
			}
		})
	}
}
