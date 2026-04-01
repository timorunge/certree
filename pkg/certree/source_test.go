package certree

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_classifySource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   SourceKind
	}{
		{name: "stdin", source: "-", want: SourceStdin},
		{name: "host with port", source: "example.com:443", want: SourceHost},
		{name: "host with custom port", source: "example.com:8443", want: SourceHost},
		{name: "bare hostname", source: "example.com", want: SourceHost},
		{name: "subdomain", source: "sub.example.com", want: SourceHost},
		{name: "absolute path", source: "/etc/ssl/cert.pem", want: SourceFile},
		{name: "relative path with slash", source: "certs/cert.pem", want: SourceFile},
		{name: "windows path", source: "C:\\certs\\cert.pem", want: SourceFile},
		{name: "plain word no dot", source: "localhost", want: SourceFile},
		{name: "single word no dot", source: "certificate", want: SourceFile},
		{name: "dotslash relative", source: "./cert.pem", want: SourceFile},
		{name: "dotdot relative", source: "../cert.pem", want: SourceFile},

		// URL sources.
		{name: "https url", source: "https://pki.example.com/ca.pem", want: SourceURL},
		{name: "http url", source: "http://pki.example.com/ca.crt", want: SourceURL},
		{name: "https url with port", source: "https://pki.example.com:8443/ca.pem", want: SourceURL},
		{name: "bare host/path inferred url", source: "pki.example.com/ca-bundle.pem", want: SourceURL},
		{name: "bare host/path deep", source: "example.com/certs/chain.pem", want: SourceURL},
		{name: "host port path", source: "i.pki.goog:443/r1.pem", want: SourceURL},
		{name: "host custom port path", source: "pki.example.com:8080/ca.crt", want: SourceURL},

		// Paths that should NOT be URLs.
		{name: "relative dir no dot in prefix", source: "certs/chain.pem", want: SourceFile},

		// Certificate file extensions classify as file.
		{name: "bare pem", source: "cert.pem", want: SourceFile},
		{name: "bare crt", source: "cert.crt", want: SourceFile},
		{name: "bare der", source: "cert.der", want: SourceFile},
		{name: "bare p12", source: "cert.p12", want: SourceFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifySource(tt.source)
			if got != tt.want {
				t.Errorf("classifySource(%q) = %d, want %d", tt.source, got, tt.want)
			}
		})
	}
}

func Test_classifySource_AllCertExtensions(t *testing.T) {
	t.Parallel()

	for _, ext := range certFileExtensions {
		t.Run(ext, func(t *testing.T) {
			t.Parallel()
			source := "cert" + ext
			got := classifySource(source)
			if got != SourceFile {
				t.Errorf("classifySource(%q) = %d, want SourceFile", source, got)
			}
		})
	}
}

func TestNormalizeSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "bare hostname", source: "example.com", want: "example.com:443"},
		{name: "host with port", source: "example.com:8443", want: "example.com:8443"},
		{name: "bare host/path", source: "pki.example.com/ca.pem", want: "https://pki.example.com/ca.pem"},
		{name: "explicit https", source: "https://pki.example.com/ca.pem", want: "https://pki.example.com/ca.pem"},
		{name: "explicit http", source: "http://pki.example.com/ca.pem", want: "http://pki.example.com/ca.pem"},
		{name: "file unchanged", source: "/path/to/cert.pem", want: "/path/to/cert.pem"},
		{name: "stdin unchanged", source: "-", want: "-"},
		{name: "cert extension", source: "cert.pem", want: "cert.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeSource(tt.source)
			if got != tt.want {
				t.Errorf("NormalizeSource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func Test_isHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "domain with dot", source: "example.com", want: true},
		{name: "subdomain", source: "a.b.c.com", want: true},
		{name: "domain with port", source: "example.com:443", want: true},
		{name: "no dot", source: "localhost", want: false},
		{name: "pem extension", source: "file.pem", want: false},
		{name: "crt extension", source: "file.crt", want: false},
		{name: "spaces", source: "not a hostname", want: false},
		{name: "special chars", source: "host_name.com", want: false},
		{name: "starts with hyphen", source: "-example.com", want: false},
		{name: "ends with hyphen", source: "example-.com", want: true},
		{name: "non-numeric port", source: "host.local:abc", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isHostname(tt.source)
			if got != tt.want {
				t.Errorf("isHostname(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func Test_isFilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "absolute", source: "/etc/ssl/cert.pem", want: true},
		{name: "dotslash", source: "./cert.pem", want: true},
		{name: "dotdot", source: "../cert.pem", want: true},
		{name: "windows drive", source: "C:\\certs\\cert.pem", want: true},
		{name: "windows forward slash", source: "C:/certs/cert.pem", want: true},
		{name: "backslash in path", source: "certs\\cert.pem", want: true},
		{name: "bare filename", source: "cert.pem", want: false},
		{name: "hostname", source: "example.com", want: false},
		{name: "empty", source: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isFilePath(tt.source)
			if got != tt.want {
				t.Errorf("isFilePath(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func Test_isIPAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "ipv4", source: "192.168.1.1", want: true},
		{name: "ipv4 with port", source: "192.168.1.1:443", want: true},
		{name: "ipv4 loopback", source: "127.0.0.1", want: true},
		{name: "ipv6 full", source: "::1", want: true},
		{name: "ipv6 bracketed port", source: "[::1]:443", want: true},
		{name: "hostname", source: "example.com", want: false},
		{name: "hostname with port", source: "example.com:443", want: false},
		{name: "empty", source: "", want: false},
		{name: "bare word", source: "localhost", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isIPAddress(tt.source)
			if got != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func TestValidateSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		source    string
		wantErr   bool
		errSubstr string
	}{
		{name: "stdin", source: "-"},
		{name: "hostname", source: "example.com"},
		{name: "hostname with port", source: "example.com:443"},
		{name: "subdomain", source: "sub.example.com"},
		{name: "https url", source: "https://pki.example.com/ca.pem"},
		{name: "ipv4", source: "192.168.1.1"},
		{name: "ipv4 with port", source: "192.168.1.1:443"},
		{name: "ipv6 bracketed", source: "[::1]:443"},
		{name: "host path url", source: "pki.example.com/ca.pem"},
		{name: "file path", source: "/etc/ssl/cert.pem"},
		{name: "bare cert file", source: "cert.pem"},

		// Non-existent files pass through -- the parser will give a proper
		// StructuredError. Validation only rejects files it can open and sniff.
		{name: "nonexistent pem", source: "/nonexistent/cert.pem"},
		{name: "nonexistent bare", source: "nonexistent.pem"},

		// Rejected sources.
		{name: "http url", source: "http://pki.example.com/ca.pem", wantErr: true, errSubstr: "use https://"},
		{name: "passwd line", source: "root:x:0:0:root:/root:/bin/bash", wantErr: true, errSubstr: "unrecognized source"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateSource(tt.source)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetectSource_LocalFileOverride(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ambiguous := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(ambiguous, []byte("module test\n"), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	got := DetectSource(ambiguous)
	if got != SourceFile {
		t.Errorf("DetectSource(%q) = %d, want SourceFile (local file should override hostname)", ambiguous, got)
	}
}

func TestDetectSource_NonexistentHostname(t *testing.T) {
	t.Parallel()

	// A hostname-like string that doesn't exist on disk stays SourceHost.
	got := DetectSource("example.com")
	if got != SourceHost {
		t.Errorf("DetectSource(%q) = %d, want SourceHost", "example.com", got)
	}
}

func TestSecurityValidateSource_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("source over 4096 bytes", func(t *testing.T) {
		t.Parallel()
		// A source longer than maxSourceLength likely means the caller
		// accidentally passed file contents as a source argument.
		source := strings.Repeat("a", maxSourceLength+1)
		err := ValidateSource(source)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidInput),
			"oversized source must return ErrInvalidInput, got: %v", err)
	})

	t.Run("source with null bytes", func(t *testing.T) {
		t.Parallel()
		// Null bytes could bypass hostname/path parsing in C-string based syscalls.
		source := "example.com\x00evil.com"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with embedded newlines", func(t *testing.T) {
		t.Parallel()
		// Newlines could inject log lines or confuse line-oriented parsers.
		source := "example.com\nevil.com"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with shell metacharacters semicolon", func(t *testing.T) {
		t.Parallel()
		source := "example.com;rm -rf /"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with shell metacharacter pipe", func(t *testing.T) {
		t.Parallel()
		source := "example.com|cat /etc/passwd"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with shell metacharacter ampersand", func(t *testing.T) {
		t.Parallel()
		source := "example.com&background"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with dollar sign variable expansion", func(t *testing.T) {
		t.Parallel()
		source := "example.com$PATH"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with backtick command substitution", func(t *testing.T) {
		t.Parallel()
		source := "example.com`whoami`"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source with unicode and emoji", func(t *testing.T) {
		t.Parallel()
		// IDN hostnames are not supported; reject rather than silently ignore.
		source := "example.com\U0001F4A9"
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("source that is just spaces", func(t *testing.T) {
		t.Parallel()
		source := "     "
		err := ValidateSource(source)
		require.Error(t, err)
	})

	t.Run("stdin marker is accepted", func(t *testing.T) {
		t.Parallel()
		// "-" is the conventional stdin marker and must pass validation.
		err := ValidateSource("-")
		assert.NoError(t, err)
	})
}
