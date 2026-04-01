package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree"
)

// errorReader is an io.Reader that always returns the configured error.
type errorReader struct {
	err error
}

// Read always returns zero bytes and the configured error.
func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

// writeTempBatchFile writes a batch file with the given sources to a temp
// directory. Returns the file path.
func writeTempBatchFile(t *testing.T, dir string, sources []string) string {
	t.Helper()

	content := strings.Join(sources, "\n") + "\n"
	path := filepath.Join(dir, "sources.txt")
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err, "writing batch file")

	return path
}

func TestResolveSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		positional []string
		batch      []string
		hostsFile  string
		wantSrcs   []string
		wantErr    bool
		errSubstr  string
	}{
		{
			name:       "positional and batch combined preserves order",
			positional: []string{"github.com"},
			batch:      []string{"cloudflare.com"},
			wantSrcs:   []string{"github.com", "cloudflare.com"},
		},
		{
			name:       "batch only no positional",
			positional: []string{},
			batch:      []string{"example.com", "cloudflare.com"},
			wantSrcs:   []string{"example.com", "cloudflare.com"},
		},
		{
			name:       "no sources at all returns empty slice",
			positional: []string{},
			batch:      nil,
			wantSrcs:   []string{},
		},
		{
			name:       "cross-list stdin duplicate rejected",
			positional: []string{"-"},
			batch:      []string{"-"},
			wantErr:    true,
			errSubstr:  "stdin (-) can only be specified once",
		},
		{
			name:       "positional only no batch",
			positional: []string{"example.com"},
			batch:      nil,
			wantSrcs:   []string{"example.com"},
		},
		{
			name:       "multiple positional with batch preserves full order",
			positional: []string{"a.com", "b.com"},
			batch:      []string{"c.com", "d.com"},
			wantSrcs:   []string{"a.com", "b.com", "c.com", "d.com"},
		},
		{
			name:       "stdin with other sources",
			positional: []string{"-", "example.com"},
			batch:      nil,
			wantErr:    true,
			errSubstr:  "stdin (-) cannot be combined with other sources",
		},
		{
			name:       "unreadable batch file",
			positional: []string{},
			hostsFile:  "/nonexistent/path/sources.txt",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostsFile := tt.hostsFile
			if tt.batch != nil {
				dir := t.TempDir()
				hostsFile = writeTempBatchFile(t, dir, tt.batch)
			}

			srcs, err := resolveSources(tt.positional, hostsFile)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSrcs, srcs, "resolved sources")
		})
	}
}

func TestAnalyzeStdin_EmptyInput(t *testing.T) {
	t.Parallel()

	reader := bytes.NewReader(nil)
	analysis, code, err := analyzeStdin(t.Context(), nil, 30*time.Second, reader)

	assert.Nil(t, analysis, "analysis must be nil on empty input")
	assert.Equal(t, exitUsageError, code, "exit code must be exitUsageError for empty input")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data on stdin")
}

func TestAnalyzeStdin_ReadFailure(t *testing.T) {
	t.Parallel()

	readErr := errors.New("simulated read failure")
	reader := &errorReader{err: readErr}
	analysis, code, err := analyzeStdin(t.Context(), nil, 30*time.Second, reader)

	assert.Nil(t, analysis, "analysis must be nil on read failure")
	assert.Equal(t, exitParseError, code, "exit code must be exitParseError")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading stdin")
	assert.ErrorIs(t, err, readErr, "original error must be in the chain")
}

func TestLoadSourcesFromFile_IPAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "IPv4 bare",
			content:  "192.168.1.1\n",
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "IPv4 with port",
			content:  "192.168.1.1:443\n",
			expected: []string{"192.168.1.1:443"},
		},
		{
			name:     "IPv6 bracketed with port",
			content:  "[::1]:443\n",
			expected: []string{"[::1]:443"},
		},
		{
			name:     "IPv4 loopback",
			content:  "127.0.0.1:8443\n",
			expected: []string{"127.0.0.1:8443"},
		},
		{
			name: "mixed hostnames and IPs",
			content: strings.Join([]string{
				"example.com:443",
				"192.168.1.100:443",
				"10.0.0.1",
				"[::1]:443",
				"api.example.com",
			}, "\n") + "\n",
			expected: []string{
				"example.com:443",
				"192.168.1.100:443",
				"10.0.0.1",
				"[::1]:443",
				"api.example.com",
			},
		},
		{
			name: "IPs with comments and blank lines",
			content: strings.Join([]string{
				"# Production servers",
				"192.168.1.1:443",
				"",
				"# Staging",
				"10.0.0.5:443",
				"",
			}, "\n"),
			expected: []string{"192.168.1.1:443", "10.0.0.5:443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			batchPath := filepath.Join(dir, "sources.txt")
			require.NoError(t, os.WriteFile(batchPath, []byte(tt.content), 0600))

			sources, err := loadSourcesFromFile(batchPath)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, sources)
		})
	}
}

func TestLoadSourcesFromFile_InvalidSource(t *testing.T) {
	t.Parallel()

	// First-line failures: when the first non-comment entry is invalid,
	// the error should indicate the whole file is not a valid sources file.
	t.Run("first line invalid gives file-level error", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			content string
		}{
			{name: "semicolon injection", content: "example.com; rm -rf /\n"},
			{name: "passwd line", content: "root:x:0:0:root:/root:/bin/bash\n"},
			{name: "bare word", content: "certificate\n"},
			{name: "http url", content: "http://pki.example.com/ca.pem\n"},
			{name: "yaml config", content: "version: 2\n"},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()
				batchPath := filepath.Join(dir, "sources.txt")
				require.NoError(t, os.WriteFile(batchPath, []byte(tt.content), 0600))

				_, err := loadSourcesFromFile(batchPath)
				require.Error(t, err, "expected error for %s", tt.name)
				assert.Contains(t, err.Error(), "does not appear to be a valid sources file")
			})
		}
	})

	// Later-line failures: when the first entry is valid but a later line
	// is invalid, the error should report the specific line number.
	t.Run("later line invalid gives line-level error", func(t *testing.T) {
		t.Parallel()

		content := "example.com\nbadline!;\n"
		dir := t.TempDir()
		batchPath := filepath.Join(dir, "sources.txt")
		require.NoError(t, os.WriteFile(batchPath, []byte(content), 0600))

		_, err := loadSourcesFromFile(batchPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "line 2")
	})

	// Content sniff case: batch file references an existing non-cert file.
	t.Run("existing non-cert file as source", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		nonCertPath := filepath.Join(dir, "notes.txt")
		require.NoError(t, os.WriteFile(nonCertPath, []byte("just some notes\n"), 0600))

		batchPath := filepath.Join(dir, "sources.txt")
		require.NoError(t, os.WriteFile(batchPath, []byte(nonCertPath+"\n"), 0600))

		_, err := loadSourcesFromFile(batchPath)
		require.Error(t, err, "batch file referencing non-cert file must be rejected")
		assert.Contains(t, err.Error(), "does not appear to be a valid sources file")
	})
}

func TestValidateBatchLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid hostname", input: "example.com", wantErr: false},
		{name: "hostname with port", input: "example.com:443", wantErr: false},
		{name: "IPv4", input: "192.168.1.1", wantErr: false},
		{name: "IPv4 with port", input: "192.168.1.1:443", wantErr: false},
		{name: "IPv6 bracketed with port", input: "[::1]:443", wantErr: false},
		{name: "IPv4 loopback", input: "127.0.0.1", wantErr: false},
		{name: "semicolon", input: "host;cmd", wantErr: true},
		{name: "pipe", input: "host|cmd", wantErr: true},
		{name: "ampersand", input: "host&cmd", wantErr: true},
		{name: "dollar", input: "host$var", wantErr: true},
		{name: "backtick", input: "host`cmd`", wantErr: true},
		{name: "newline", input: "host\ncmd", wantErr: true},
		{name: "null byte", input: "host\x00cmd", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateBatchLine(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBatchLine(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSource_ContentSniff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0600))
		return p
	}

	pemFile := writeFile("cert.pem", "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
	derFile := writeFile("cert.der", "\x30\x82\x03\x00fake DER data")
	passwdFile := writeFile("passwd", "root:x:0:0:root:/root:/bin/bash\n")
	jsonFile := writeFile("config.json", `{"key": "value"}`)
	scriptFile := writeFile("script.sh", "#!/bin/bash\necho hello\n")
	renamedFile := writeFile("evil.pem", "root:x:0:0:root:/root:/bin/bash\n")
	emptyFile := writeFile("empty.pem", "")
	hostnameLikeFile := writeFile("go.mod", "module example.com/foo\n\ngo 1.24\n")

	tests := []struct {
		name      string
		source    string
		wantErr   bool
		errSubstr string
	}{
		{name: "valid pem", source: pemFile},
		{name: "valid der", source: derFile},
		{name: "passwd content", source: passwdFile, wantErr: true, errSubstr: "does not contain certificate data"},
		{name: "json content", source: jsonFile, wantErr: true, errSubstr: "does not contain certificate data"},
		{name: "shell script", source: scriptFile, wantErr: true, errSubstr: "does not contain certificate data"},
		{name: "renamed passwd as pem", source: renamedFile, wantErr: true, errSubstr: "does not contain certificate data"},
		{name: "empty file", source: emptyFile, wantErr: true, errSubstr: "is empty"},
		{name: "hostname-like file", source: hostnameLikeFile, wantErr: true, errSubstr: "does not contain certificate data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := certree.ValidateSource(tt.source)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadSourcesFromFile_CRLFLineEndings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	batchPath := filepath.Join(dir, "sources.txt")
	require.NoError(t, os.WriteFile(batchPath, []byte("example.com\r\ntest.com\r\n"), 0600))

	sources, err := loadSourcesFromFile(batchPath)
	require.NoError(t, err)

	expected := []string{"example.com", "test.com"}
	assert.Equal(t, expected, sources)
	for i, got := range sources {
		assert.False(t, strings.Contains(got, "\r"), "source[%d] contains trailing \\r: %q", i, got)
	}
}

func TestContainsPathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "bare dotdot", input: "..", want: true},
		{name: "dotdot slash", input: "../", want: true},
		{name: "slash dotdot", input: "/..", want: true},
		{name: "slash dotdot slash", input: "/../", want: true},
		{name: "dotdot in middle forward slash", input: "foo/../bar", want: true},
		{name: "dotdot in middle backslash", input: "foo\\..\\bar", want: true},
		{name: "mixed separators forward then back", input: "foo/..\\bar", want: true},
		{name: "mixed separators complex", input: "foo\\..\\/bar", want: true},
		{name: "normal path", input: "normal/path", want: false},
		{name: "dotdot prefix no separator", input: "..file", want: false},
		{name: "dotdot suffix no separator", input: "file..", want: false},
		{name: "dotdot in filename no separator", input: "path/to/..cert.pem", want: false},
		{name: "empty string", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, containsPathTraversal(tt.input))
		})
	}
}

func TestLoadSourcesFromFile_FileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	batchPath := filepath.Join(dir, "sources.txt")
	require.NoError(t, os.WriteFile(batchPath, nil, 0600))
	require.NoError(t, os.Truncate(batchPath, int64(maxSourceFileSize)+1))

	_, err := loadSourcesFromFile(batchPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, certree.ErrFileTooLarge)
}
