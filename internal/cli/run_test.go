package cli

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// writeTempChainPEM generates a 3-cert chain (end-entity, intermediate, root)
// and writes all three PEM blocks to a single temp file. Returns the file path
// and the common name of the root CA so tests can exclude it via --exclude-cn.
func writeTempChainPEM(t *testing.T, dir string) (path, rootCN string) {
	t.Helper()

	certs, _, err := testutil.GenerateSimpleChain()
	require.NoError(t, err, "generating simple chain")

	pemData := testutil.EncodePEMChain(certs)
	path = filepath.Join(dir, "chain.pem")
	err = os.WriteFile(path, pemData, 0600)
	require.NoError(t, err, "writing chain PEM file")

	// certs[2] is the root CA.
	rootCN = certs[2].Subject.CommonName
	return path, rootCN
}

// writeTempPEM generates a self-signed certificate and writes it to a temp PEM
// file in the given directory.
func writeTempPEM(t *testing.T, dir string) string {
	t.Helper()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "test-cert.example.com"},
		IsCA:    true,
	})
	require.NoError(t, err, "generating test certificate")

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(dir, "test-cert.pem")
	err = os.WriteFile(path, pemData, 0600)
	require.NoError(t, err, "writing PEM file")

	return path
}

func TestRun_VersionFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--version"}, "test-version")

	assert.Equal(t, exitSuccess, code, "exit code")

	output := stdout.String()
	assert.Contains(t, output, "certree", "stdout must contain program name")

	lines := strings.SplitAfter(strings.TrimRight(output, "\n"), "\n")
	assert.Len(t, lines, 1, "version output must be a single line")

	assert.Equal(t, "certree test-version\n", output, "version output must match expected format")

	assert.Empty(t, stderr.String(), "stderr must be empty")
}

func TestRun_HelpShowsFieldsInDisplay(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--help"}, "test-version")

	require.Equal(t, exitSuccess, code, "exit code")
	output := stdout.String()

	assert.Contains(t, output, "--fields", "help must contain --fields flag")
	assert.Contains(t, output, "-f,", "help must contain -f shorthand")

	for _, name := range []string{"fingerprint", "serial", "validity"} {
		assert.Contains(t, output, name,
			"help must list field name %q in --fields usage", name)
	}

	exIdx := strings.Index(output, "EXAMPLES:")
	require.Greater(t, exIdx, 0, "help must contain EXAMPLES section")
	examples := output[exIdx:]
	assert.Contains(t, examples, "--fields", "EXAMPLES must include --fields usage")
	assert.Contains(t, examples, "--fields all", "EXAMPLES must include --fields all usage")

	assert.Contains(t, output, "[SOURCE ...]", "usage must show [SOURCE ...]")
	assert.NotContains(t, output, "--source", "help must not reference removed --source flag")
}

func TestRun_NoArgs(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{}, "test-version")

	assert.Equal(t, exitUsageError, code, "exit code")
	assert.Contains(t, stderr.String(), "USAGE:", "stderr must contain usage text")
	assert.Empty(t, stdout.String(), "stdout must be empty")
}

func TestRun_UnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--nonexistent-flag", "cert.pem"}, "test-version")

	assert.Equal(t, exitUsageError, code, "exit code for unknown flag")
	assert.Contains(t, stderr.String(), "unknown flag", "stderr must mention unknown flag")
	assert.Empty(t, stdout.String(), "stdout must be empty on error")
}

func TestRun_InvalidFlagValue(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	// max-depth expects an int; "abc" is invalid.
	code := Run(&stdout, &stderr, []string{"--max-depth", "abc", "cert.pem"}, "test-version")

	assert.Equal(t, exitUsageError, code, "exit code for invalid flag value")
	assert.Contains(t, stderr.String(), "[x ]", "stderr must contain error icon prefix")
	assert.Empty(t, stdout.String(), "stdout must be empty on error")
}

func TestRun_PositionalArg(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemPath := writeTempPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{pemPath}, "test-version")

	assert.Equal(t, exitValidationError, code, "exit code")
	assert.NotEmpty(t, stdout.String(), "stdout must contain output")
}

func TestRun_DiffWithoutExclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemPath := writeTempPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--diff", pemPath}, "test-version")

	assert.Equal(t, exitUsageError, code, "exit code")
	assert.Contains(t, stderr.String(), "--diff requires",
		"stderr must explain that --diff requires an exclusion flag")
	assert.Empty(t, stdout.String(), "stdout must be empty on error")
}

func TestRun_DiffQuietSuppressesOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemPath := writeTempPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"--diff", "--quiet", "--exclude-cn", "nonexistent", pemPath,
	}, "test-version")

	// Quiet mode: exit 0 or 1 depending on validation, but no output.
	assert.Empty(t, stdout.String(), "stdout must be empty in quiet mode")
	assert.Empty(t, stderr.String(), "stderr must be empty in quiet mode")
	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1 in quiet mode, got %d", code)
}

func TestRun_DiffImpact(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemPath := writeTempPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"--diff", "--impact", "--exclude-cn", "nonexistent", pemPath,
	}, "test-version")

	// The command should succeed (exit 0 or 1 depending on validation).
	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d", code)
	assert.Contains(t, stdout.String(), "Impact:",
		"stdout must contain impact summary when --impact is set")
}

func TestResolveLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cliVerbose     int
		cliChanged     bool
		configLogLevel string
		want           logLevel
	}{
		{name: "cli verbose 0", cliVerbose: 0, cliChanged: true, configLogLevel: "debug", want: logLevelOff},
		{name: "cli verbose 1", cliVerbose: 1, cliChanged: true, configLogLevel: "off", want: logLevelError},
		{name: "cli verbose 2", cliVerbose: 2, cliChanged: true, configLogLevel: "off", want: logLevelWarn},
		{name: "cli verbose 3", cliVerbose: 3, cliChanged: true, configLogLevel: "off", want: logLevelInfo},
		{name: "cli verbose 4", cliVerbose: 4, cliChanged: true, configLogLevel: "off", want: logLevelDebug},
		{name: "config info", cliVerbose: 0, cliChanged: false, configLogLevel: "info", want: logLevelInfo},
		{name: "config debug", cliVerbose: 0, cliChanged: false, configLogLevel: "debug", want: logLevelDebug},
		{name: "config warn", cliVerbose: 0, cliChanged: false, configLogLevel: "warn", want: logLevelWarn},
		{name: "config error", cliVerbose: 0, cliChanged: false, configLogLevel: "error", want: logLevelError},
		{name: "config off", cliVerbose: 0, cliChanged: false, configLogLevel: "off", want: logLevelOff},
		{name: "config empty", cliVerbose: 0, cliChanged: false, configLogLevel: "", want: logLevelOff},
		{name: "cli takes precedence over config", cliVerbose: 4, cliChanged: true, configLogLevel: "error", want: logLevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, resolveLogLevel(tt.cliVerbose, tt.cliChanged, tt.configLogLevel))
		})
	}
}

func TestRun_SimulationExcludeCN(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	chainPath, rootCN := writeTempChainPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--annotations", "--exclude-cn", rootCN, chainPath}, "test-version")

	// Exit 0 or 1 depending on whether the simulated paths have errors.
	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d", code)
	output := stdout.String()
	assert.Contains(t, output, "excluded",
		"tree output must contain 'excluded' annotation on excluded certificate")
}

func TestRun_SimulationExcludeCN_JSONFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	chainPath, rootCN := writeTempChainPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"--exclude-cn", rootCN,
		"--format", "json",
		chainPath,
	}, "test-version")

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d", code)
	assert.True(t, strings.Contains(stdout.String(), "["),
		"JSON output must begin with array bracket")
	assert.True(t, len(stdout.Bytes()) > 0, "stdout must not be empty")
}

func TestRun_SimulationExcludeCN_Compare(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	chainPath, rootCN := writeTempChainPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"--exclude-cn", rootCN,
		"--compare",
		chainPath,
	}, "test-version")

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d", code)
	assert.NotEmpty(t, stdout.String(), "comparison output must not be empty")
}

func TestRun_SimulationExcludeCN_Quiet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	chainPath, rootCN := writeTempChainPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"--exclude-cn", rootCN,
		"--quiet",
		chainPath,
	}, "test-version")

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1 in quiet mode, got %d", code)
	assert.Empty(t, stdout.String(), "stdout must be empty in quiet mode")
	assert.Empty(t, stderr.String(), "stderr must be empty in quiet mode")
}

func TestRun_StdinPEM(t *testing.T) {
	certs, _, err := testutil.GenerateSimpleChain()
	require.NoError(t, err, "generating simple chain")

	pemData := testutil.EncodePEMChain(certs)

	// Create a pipe, write PEM data to the write end, then close it so that
	// readers receive EOF after consuming all data.
	pr, pw, err := os.Pipe()
	require.NoError(t, err, "creating OS pipe")

	_, err = pw.Write(pemData)
	require.NoError(t, err, "writing PEM to pipe")
	require.NoError(t, pw.Close(), "closing pipe write end")

	// Swap os.Stdin and restore it when the test ends.
	origStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = origStdin
		_ = pr.Close()
	})

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"-"}, "test-version")

	// Exit 0 (all paths trusted) or 1 (validation errors) are both acceptable;
	// any other code indicates a pipeline failure.
	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d (stderr: %s)", code, stderr.String())

	// The end-entity CN must appear in the tree output.
	endEntityCN := certs[0].Subject.CommonName
	assert.Contains(t, stdout.String(), endEntityCN,
		"stdout must contain end-entity CN %q", endEntityCN)
}

func TestRun_BatchFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Write two PEM files to distinct sub-directories to avoid the fixed
	// filename collision in writeTempPEM.
	dir1 := filepath.Join(dir, "a")
	require.NoError(t, os.MkdirAll(dir1, 0700))
	pem1 := writeTempPEM(t, dir1)

	dir2 := filepath.Join(dir, "b")
	require.NoError(t, os.MkdirAll(dir2, 0700))
	pem2 := writeTempPEM(t, dir2)

	// Write a batch file listing both paths, one per line.
	batchPath := filepath.Join(dir, "batch.txt")
	batchContent := fmt.Sprintf("%s\n%s\n", pem1, pem2)
	require.NoError(t, os.WriteFile(batchPath, []byte(batchContent), 0600))

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--batch", batchPath}, "test-version")

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d (stderr: %s)", code, stderr.String())
	assert.NotEmpty(t, stdout.String(), "stdout must contain output")
	assert.Contains(t, stdout.String(), " -- ",
		"stdout must contain root label with double-dash separator")
}

func TestRun_InjectFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	chainPath, _ := writeTempChainPEM(t, dir)

	// Write a second self-signed cert as the injected PEM.
	injectDir := filepath.Join(dir, "inject")
	require.NoError(t, os.MkdirAll(injectDir, 0700))
	injectPath := writeTempPEM(t, injectDir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"--inject", injectPath, chainPath}, "test-version")

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d (stderr: %s)", code, stderr.String())

	output := stdout.String()
	assert.NotEmpty(t, output, "stdout must contain output")
	assert.Contains(t, output, " -- ",
		"stdout must contain root label with double-dash separator")
}

func TestRun_ValidationTimeFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemPath := writeTempPEM(t, dir)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr,
		[]string{"--validation-time", "2099-01-01T00:00:00Z", pemPath},
		"test-version",
	)

	assert.True(t, code == exitSuccess || code == exitValidationError,
		"exit code must be 0 or 1, got %d (stderr: %s)", code, stderr.String())
	assert.NotEmpty(t, stdout.String(), "stdout must contain output")
}
