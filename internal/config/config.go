// Configuration types, defaults, TOML loading, and validation.

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

const (
	defaultExpiryWarningDays = certree.DefaultExpiryWarningDays
	defaultMaxCertificates   = certree.DefaultMaxCertificates
	defaultMaxDepth          = certree.DefaultMaxDepth
	defaultTheme             = render.DefaultThemeName
	defaultColor             = ColorAuto
	defaultFormat            = FormatTree
	defaultLogLevel          = "off"

	// FormatJSON is the JSON output format identifier.
	FormatJSON = "json"
	// FormatTree is the tree output format identifier.
	FormatTree = "tree"

	// ColorAuto enables color when output is a terminal.
	ColorAuto = "auto"
	// ColorAlways forces color output on.
	ColorAlways = "always"
	// ColorNever disables color output.
	ColorNever = "never"

	maxTimeout           = 5 * time.Minute
	maxMaxCertificates   = 10000
	maxMaxDepth          = 100
	maxExpiryWarningDays = 3650
)

// Variables because time.Duration.String() is not a constant expression.
var (
	defaultConnectTimeout = certree.DefaultConnectTimeout.String()
	defaultAIATimeout     = certree.DefaultAIATimeout.String()
	defaultFetchTimeout   = certree.DefaultURLFetchTimeout.String()
)

// Config is the top-level configuration for the certree CLI.
type Config struct {
	Connection ConnectionConfig `toml:"connection"`
	Validation ValidationConfig `toml:"validation"`
	Render     RenderConfig     `toml:"render"`
	Output     OutputConfig     `toml:"output"`
	TrustStore TrustStoreConfig `toml:"trust_store"`
}

// ConnectionConfig controls network behavior for remote host analysis.
type ConnectionConfig struct {
	ConnectTimeout       string `toml:"connect_timeout"`
	FetchTimeout         string `toml:"fetch_timeout"`
	SNI                  string `toml:"sni"`
	ClientCert           string `toml:"client_cert"`
	ClientKey            string `toml:"client_key"`
	AIAFetch             bool   `toml:"aia_fetch"`
	AIAForce             bool   `toml:"aia_force"`
	AIATimeout           string `toml:"aia_timeout"`
	AllowPrivateNetworks bool   `toml:"allow_private_networks"`
}

// ValidationConfig controls certificate validation behavior.
type ValidationConfig struct {
	VerifySignatures      bool   `toml:"verify_signatures"`
	VerifyExpiry          bool   `toml:"verify_expiry"`
	ExpiryWarningDays     int    `toml:"expiry_warning_days"`
	MaxValidityDays       int    `toml:"max_validity_days"`
	VerifyHostname        bool   `toml:"verify_hostname"`
	Hostname              string `toml:"hostname"`
	VerifyRevocation      bool   `toml:"verify_revocation"`
	RevocationFailOpen    bool   `toml:"revocation_fail_open"`
	VerifyEKU             bool   `toml:"verify_eku"`
	VerifyNameConstraints bool   `toml:"verify_name_constraints"`
	MaxCertificates       int    `toml:"max_certificates"`
	// MaxDepth limits chain building recursion depth. Must be >= 1;
	// the library's 0-means-unlimited semantic is intentionally blocked.
	MaxDepth    int  `toml:"max_depth"`
	SkipInvalid bool `toml:"skip_invalid"`
}

// RenderConfig controls visualization behavior.
type RenderConfig struct {
	Theme       string `toml:"theme"`
	Fields      string `toml:"fields"`
	Reverse     bool   `toml:"reverse"`
	Annotations bool   `toml:"annotations"`
	PathIndex   bool   `toml:"path_index"`
	Expand      bool   `toml:"expand"`
	Wrap        bool   `toml:"wrap"`
}

// OutputConfig controls output format and color.
type OutputConfig struct {
	Color    string `toml:"color"`
	Format   string `toml:"format"`
	LogLevel string `toml:"log_level"`
}

// TrustStoreConfig controls trust store behavior.
type TrustStoreConfig struct {
	SystemRoots       string `toml:"system_roots"`
	TrustBundle       string `toml:"trust_bundle"`
	PreferCustomRoots bool   `toml:"prefer_custom_roots"`
}

// DefaultConfig returns a Config with sensible defaults for all fields.
func DefaultConfig() *Config {
	return &Config{
		Connection: ConnectionConfig{
			ConnectTimeout: defaultConnectTimeout,
			FetchTimeout:   defaultFetchTimeout,
			AIAFetch:       false,
			AIAForce:       false,
			AIATimeout:     defaultAIATimeout,
		},
		Validation: ValidationConfig{
			VerifyExpiry:       true,
			ExpiryWarningDays:  defaultExpiryWarningDays,
			MaxCertificates:    defaultMaxCertificates,
			MaxDepth:           defaultMaxDepth,
			RevocationFailOpen: true,
			SkipInvalid:        false,
			VerifyHostname:     true,
			VerifySignatures:   true,
		},
		Render: RenderConfig{
			Theme: defaultTheme,
		},
		Output: OutputConfig{
			Color:    defaultColor,
			Format:   defaultFormat,
			LogLevel: defaultLogLevel,
		},
	}
}

// LoadConfig loads configuration from an explicit file path, or returns
// DefaultConfig if configPath is empty.
func LoadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		return DefaultConfig(), nil
	}
	return loadConfigFromFile(configPath)
}

// loadConfigFromFile decodes TOML into DefaultConfig(), so absent fields keep defaults.
func loadConfigFromFile(path string) (*Config, error) {
	path = filepath.Clean(path)

	// #nosec G304 -- File path comes from explicit user input via --config flag, cleaned above.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %s not found", path)
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return DefaultConfig(), nil
	}

	cfg := DefaultConfig()
	meta, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config file %s: %s", path, humanizeTOMLError(err))
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("parsing config file %s: unknown field %q", path, undecoded[0])
	}

	return cfg, nil
}

// Validate checks connection, validation, output format/color, and log-level
// settings against their allowed ranges. Theme and field names are validated
// at use time by the render and CLI packages.
func (c *Config) Validate() error {
	if err := c.validateConnection(); err != nil {
		return err
	}

	if c.Validation.MaxValidityDays < 0 || c.Validation.MaxValidityDays > 36500 {
		return fmt.Errorf("max validity days must be between 0 and 36500, got %d", c.Validation.MaxValidityDays)
	}

	if c.Validation.ExpiryWarningDays < 1 {
		return fmt.Errorf("expiry warning days must be at least 1, got %d", c.Validation.ExpiryWarningDays)
	}
	if c.Validation.ExpiryWarningDays > maxExpiryWarningDays {
		return fmt.Errorf("expiry warning days must not exceed %d, got %d", maxExpiryWarningDays, c.Validation.ExpiryWarningDays)
	}
	if c.Validation.MaxCertificates < 1 {
		return fmt.Errorf("max certificates must be at least 1, got %d", c.Validation.MaxCertificates)
	}
	if c.Validation.MaxCertificates > maxMaxCertificates {
		return fmt.Errorf("max certificates must not exceed %d, got %d", maxMaxCertificates, c.Validation.MaxCertificates)
	}
	if c.Validation.MaxDepth < 1 {
		return fmt.Errorf("max depth must be at least 1, got %d", c.Validation.MaxDepth)
	}
	if c.Validation.MaxDepth > maxMaxDepth {
		return fmt.Errorf("max depth must not exceed %d, got %d", maxMaxDepth, c.Validation.MaxDepth)
	}

	switch c.Output.Format {
	case FormatTree, FormatJSON:
	default:
		return fmt.Errorf("invalid format %q: valid values are %s, %s", c.Output.Format, FormatTree, FormatJSON)
	}

	switch c.Output.Color {
	case ColorAuto, ColorAlways, ColorNever:
	default:
		return fmt.Errorf("invalid color %q: valid values are %s, %s, %s", c.Output.Color, ColorAuto, ColorAlways, ColorNever)
	}

	switch c.Output.LogLevel {
	case "", defaultLogLevel, "error", "warn", "info", "debug":
	default:
		return fmt.Errorf("invalid log_level %q: valid values are off, error, warn, info, debug", c.Output.LogLevel)
	}

	return nil
}

// validateConnection checks connection-related configuration fields.
func (c *Config) validateConnection() error {
	d, err := time.ParseDuration(c.Connection.ConnectTimeout)
	if err != nil {
		return fmt.Errorf("invalid connect timeout %q: must be a Go duration like \"5s\" or \"30s\"", c.Connection.ConnectTimeout)
	}
	if d <= 0 {
		return fmt.Errorf("connect timeout must be positive, got %s", c.Connection.ConnectTimeout)
	}
	if d > maxTimeout {
		return fmt.Errorf("connect timeout must not exceed %s, got %s", maxTimeout, c.Connection.ConnectTimeout)
	}

	fetchTimeout, err := time.ParseDuration(c.Connection.FetchTimeout)
	if err != nil {
		return fmt.Errorf("invalid fetch timeout %q: must be a Go duration like \"5s\" or \"30s\"", c.Connection.FetchTimeout)
	}
	if fetchTimeout <= 0 {
		return fmt.Errorf("fetch timeout must be positive, got %s", c.Connection.FetchTimeout)
	}
	if fetchTimeout > maxTimeout {
		return fmt.Errorf("fetch timeout must not exceed %s, got %s", maxTimeout, c.Connection.FetchTimeout)
	}

	aiaTimeout, err := time.ParseDuration(c.Connection.AIATimeout)
	if err != nil {
		return fmt.Errorf("invalid aia timeout %q: must be a Go duration like \"5s\" or \"30s\"", c.Connection.AIATimeout)
	}
	if aiaTimeout <= 0 {
		return fmt.Errorf("aia timeout must be positive, got %s", c.Connection.AIATimeout)
	}
	if aiaTimeout > maxTimeout {
		return fmt.Errorf("aia timeout must not exceed %s, got %s", maxTimeout, c.Connection.AIATimeout)
	}

	if (c.Connection.ClientCert != "") != (c.Connection.ClientKey != "") {
		return fmt.Errorf("client_cert and client_key must be specified together")
	}

	return nil
}

// humanizeTOMLError rewrites TOML library error messages that expose Go type
// internals into user-friendly messages. For example, "toml: cannot store
// TOML integer into a Go string" becomes a message about wrong value types.
func humanizeTOMLError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "cannot store TOML") {
		// Typical: "toml: cannot store TOML integer into a Go string"
		msg = strings.ReplaceAll(msg, "a Go ", "")
		msg = strings.ReplaceAll(msg, "toml: cannot store ", "wrong value type: expected ")
		msg = strings.ReplaceAll(msg, " into ", ", got ")
		return msg
	}
	if strings.Contains(msg, "incompatible types") {
		// Typical: "incompatible types: TOML value has type string; destination has type boolean"
		msg = strings.ReplaceAll(msg, "destination has type ", "expected ")
		msg = strings.ReplaceAll(msg, "TOML value has type ", "got ")
		return msg
	}
	return msg
}
