package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	require.NotNil(t, cfg, "DefaultConfig must not return nil")

	assert.Equal(t, "5s", cfg.Connection.ConnectTimeout)
	assert.Equal(t, "", cfg.Connection.SNI)
	assert.False(t, cfg.Connection.AIAFetch)
	assert.False(t, cfg.Connection.AIAForce)
	assert.Equal(t, "5s", cfg.Connection.AIATimeout)
	assert.Equal(t, "", cfg.Connection.ClientCert)
	assert.Equal(t, "", cfg.Connection.ClientKey)
	assert.False(t, cfg.Connection.AllowPrivateNetworks)

	assert.True(t, cfg.Validation.VerifySignatures)
	assert.True(t, cfg.Validation.VerifyExpiry)
	assert.Equal(t, 30, cfg.Validation.ExpiryWarningDays)
	assert.Equal(t, 0, cfg.Validation.MaxValidityDays)
	assert.True(t, cfg.Validation.VerifyHostname)
	assert.Equal(t, "", cfg.Validation.Hostname)
	assert.False(t, cfg.Validation.VerifyRevocation)
	assert.True(t, cfg.Validation.RevocationFailOpen)
	assert.False(t, cfg.Validation.VerifyEKU)
	assert.False(t, cfg.Validation.VerifyNameConstraints)
	assert.Equal(t, 100, cfg.Validation.MaxCertificates)
	assert.Equal(t, 10, cfg.Validation.MaxDepth)
	assert.False(t, cfg.Validation.SkipInvalid)

	assert.Equal(t, "classic", cfg.Render.Theme)
	assert.Equal(t, "", cfg.Render.Fields)
	assert.False(t, cfg.Render.Reverse)

	assert.Equal(t, "tree", cfg.Output.Format)
	assert.Equal(t, "auto", cfg.Output.Color)
	assert.Equal(t, "off", cfg.Output.LogLevel)

	assert.Equal(t, "", cfg.TrustStore.TrustBundle)
	assert.Equal(t, "", cfg.TrustStore.SystemRoots)
	assert.False(t, cfg.TrustStore.PreferCustomRoots)
}

func TestLoadConfigFromFile_ValidTOML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[connection]
connect_timeout = "30s"
sni = "example.com"
aia_fetch = true

[validation]
max_depth = 20
verify_revocation = true
revocation_fail_open = false
verify_signatures = false
verify_expiry = false
hostname = "example.com"
expiry_warning_days = 60

[render]
fields = "all"

[output]
format = "json"
color = "never"

[trust_store]
trust_bundle = "/path/to/bundle.pem"
`
	err := os.WriteFile(cfgPath, []byte(tomlContent), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "30s", cfg.Connection.ConnectTimeout)
	assert.True(t, cfg.Connection.AIAFetch)
	assert.Equal(t, 20, cfg.Validation.MaxDepth)
	assert.False(t, cfg.Validation.RevocationFailOpen)
	assert.False(t, cfg.Validation.VerifySignatures)
	assert.Equal(t, "example.com", cfg.Validation.Hostname)
	assert.Equal(t, "all", cfg.Render.Fields)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.Equal(t, "/path/to/bundle.pem", cfg.TrustStore.TrustBundle)
}

func TestLoadConfigFromFile_InvalidTOML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.toml")

	err := os.WriteFile(cfgPath, []byte("[connection\nbroken"), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), cfgPath)
}

func TestLoadConfigFromFile_MissingFile(t *testing.T) {
	t.Parallel()

	// Use filepath.Join so the path is absolute and uses the correct separator
	// on all platforms (Windows uses backslashes).
	cfgPath := filepath.Join(t.TempDir(), "nonexistent", "config.toml")
	cfg, err := loadConfigFromFile(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), cfgPath)
}

func TestLoadConfigFromFile_PartialTOML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "partial.toml")

	err := os.WriteFile(cfgPath, []byte("[connection]\nconnect_timeout = \"5s\"\n"), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	require.NoError(t, err)

	defaults := DefaultConfig()
	assert.Equal(t, "5s", cfg.Connection.ConnectTimeout)
	assert.Equal(t, defaults.Validation.MaxDepth, cfg.Validation.MaxDepth)
	assert.Equal(t, defaults.Validation.RevocationFailOpen, cfg.Validation.RevocationFailOpen)
	assert.Equal(t, defaults.Output.Format, cfg.Output.Format)
}

func TestLoadConfigFromFile_UnknownFieldRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "unknown.toml")

	content := "[connection]\nconnect_timeout = \"10s\"\nunknown_key = true\n"
	err := os.WriteFile(cfgPath, []byte(content), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), cfgPath)
}

func TestLoadConfigFromFile_ExplicitZeroIntFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zero.toml")

	content := "[validation]\nmax_certificates = 0\nmax_depth = 0\n"
	err := os.WriteFile(cfgPath, []byte(content), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, 0, cfg.Validation.MaxCertificates, "explicit max_certificates = 0 must not be ignored")
	assert.Equal(t, 0, cfg.Validation.MaxDepth, "explicit max_depth = 0 must not be ignored")

	err = cfg.Validate()
	require.Error(t, err, "max_certificates=0 or max_depth=0 must fail validation")
}

func TestLoadConfigFromFile_EmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "empty.toml")

	err := os.WriteFile(cfgPath, []byte(""), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	defaults := DefaultConfig()
	assert.Equal(t, defaults.Connection.ConnectTimeout, cfg.Connection.ConnectTimeout)
	assert.Equal(t, defaults.Validation.MaxDepth, cfg.Validation.MaxDepth)
	assert.Equal(t, defaults.Output.Format, cfg.Output.Format)
	assert.Equal(t, defaults.Render.Theme, cfg.Render.Theme)
}

func TestTOMLTypeMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	err := os.WriteFile(cfgPath, []byte("[connection]\nconnect_timeout = 42\n"), 0600)
	require.NoError(t, err)

	_, err = loadConfigFromFile(cfgPath)
	assert.Error(t, err)
}

func TestLoadConfigFromFile_ExplicitFalseBoolOverridesDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bools.toml")

	content := "[validation]\nverify_expiry = false\nverify_hostname = false\n"
	err := os.WriteFile(cfgPath, []byte(content), 0600)
	require.NoError(t, err)

	cfg, err := loadConfigFromFile(cfgPath)
	require.NoError(t, err)

	// These default to true but are explicitly set to false.
	assert.False(t, cfg.Validation.VerifyExpiry, "explicit false must override true default")
	assert.False(t, cfg.Validation.VerifyHostname, "explicit false must override true default")

	// Unmentioned bools keep their defaults.
	assert.True(t, cfg.Validation.VerifySignatures, "unset field must keep true default")
	assert.True(t, cfg.Validation.RevocationFailOpen, "unset field must keep true default")
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		modify  func(cfg *Config)
		wantErr string
	}{
		{
			name:    "defaults are valid",
			modify:  func(_ *Config) {},
			wantErr: "",
		},
		{
			name:    "invalid timeout format",
			modify:  func(cfg *Config) { cfg.Connection.ConnectTimeout = "not-a-duration" },
			wantErr: "invalid connect timeout",
		},
		{
			name:    "zero timeout is invalid",
			modify:  func(cfg *Config) { cfg.Connection.ConnectTimeout = "0s" },
			wantErr: "connect timeout must be positive",
		},
		{
			name:    "negative timeout is invalid",
			modify:  func(cfg *Config) { cfg.Connection.ConnectTimeout = "-5s" },
			wantErr: "connect timeout must be positive",
		},
		{
			name:    "negative expiry warning days",
			modify:  func(cfg *Config) { cfg.Validation.ExpiryWarningDays = -1 },
			wantErr: "expiry warning days",
		},
		{
			name:    "zero expiry warning days is invalid",
			modify:  func(cfg *Config) { cfg.Validation.ExpiryWarningDays = 0 },
			wantErr: "expiry warning days",
		},
		{
			name:    "one expiry warning day is valid",
			modify:  func(cfg *Config) { cfg.Validation.ExpiryWarningDays = 1 },
			wantErr: "",
		},
		{
			name:    "zero max certificates",
			modify:  func(cfg *Config) { cfg.Validation.MaxCertificates = 0 },
			wantErr: "max certificates",
		},
		{
			name:    "negative max certificates",
			modify:  func(cfg *Config) { cfg.Validation.MaxCertificates = -5 },
			wantErr: "max certificates",
		},
		{
			name:    "one max certificates is valid",
			modify:  func(cfg *Config) { cfg.Validation.MaxCertificates = 1 },
			wantErr: "",
		},
		{
			name:    "zero max depth",
			modify:  func(cfg *Config) { cfg.Validation.MaxDepth = 0 },
			wantErr: "max depth",
		},
		{
			name:    "one max depth is valid",
			modify:  func(cfg *Config) { cfg.Validation.MaxDepth = 1 },
			wantErr: "",
		},
		{
			name: "client cert and key both set is valid",
			modify: func(cfg *Config) {
				cfg.Connection.ClientCert = "/path/to/cert.pem"
				cfg.Connection.ClientKey = "/path/to/key.pem"
			},
			wantErr: "",
		},
		{
			name:    "client cert without key is invalid",
			modify:  func(cfg *Config) { cfg.Connection.ClientCert = "/path/to/cert.pem" },
			wantErr: "must be specified together",
		},
		{
			name:    "client key without cert is invalid",
			modify:  func(cfg *Config) { cfg.Connection.ClientKey = "/path/to/key.pem" },
			wantErr: "must be specified together",
		},
		{
			name:    "valid log level debug",
			modify:  func(cfg *Config) { cfg.Output.LogLevel = "debug" },
			wantErr: "",
		},
		{
			name:    "invalid log level verbose",
			modify:  func(cfg *Config) { cfg.Output.LogLevel = "verbose" },
			wantErr: "invalid log_level",
		},
		{
			name:    "timeout exceeds upper bound",
			modify:  func(cfg *Config) { cfg.Connection.ConnectTimeout = "10m" },
			wantErr: "must not exceed",
		},
		{
			name:    "max certificates exceeds upper bound",
			modify:  func(cfg *Config) { cfg.Validation.MaxCertificates = 10001 },
			wantErr: "must not exceed",
		},
		{
			name:    "max depth exceeds upper bound",
			modify:  func(cfg *Config) { cfg.Validation.MaxDepth = 101 },
			wantErr: "must not exceed",
		},
		{
			name:    "expiry warning days exceeds upper bound",
			modify:  func(cfg *Config) { cfg.Validation.ExpiryWarningDays = 3651 },
			wantErr: "must not exceed",
		},
		{
			name:    "max certificates at upper bound is valid",
			modify:  func(cfg *Config) { cfg.Validation.MaxCertificates = 10000 },
			wantErr: "",
		},
		{
			name:    "max depth at upper bound is valid",
			modify:  func(cfg *Config) { cfg.Validation.MaxDepth = 100 },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, strings.Contains(strings.ToLower(err.Error()), tt.wantErr),
					"error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
