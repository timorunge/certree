// Run orchestration and analyzer construction.

package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/timorunge/certree/internal/config"
	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

// Run is the testable entry point for the certree CLI. It accepts writers and
// args for testability and returns an exit code instead of calling os.Exit.
//
//nolint:gocyclo,cyclop // sequential pipeline of guard clauses, no deep nesting
func Run(stdout io.Writer, stderr io.Writer, args []string, version string) exitCode {
	fs := registerFlags()
	if err := fs.Parse(args); err != nil {
		// Flag parse errors always go to raw stderr since --quiet itself
		// may not have been parsed successfully.
		fallbackIcons := render.LookupLogIcons("", render.StderrColorEnabled())
		newErrReporter(stderr, fallbackIcons, logLevelOff).writeMessage(humanizeFlagError(err).Error())
		return exitUsageError
	}

	resolveNoBoolFlags(fs)

	// Resolve stderr suppression immediately after flag parsing. When
	// --quiet is set without -v flags, all stderr output is discarded so
	// the tool communicates exclusively via exit codes.
	errWriter := stderr
	if quiet, _ := fs.GetBool("quiet"); quiet && !fs.Changed("verbose") {
		errWriter = io.Discard
	}

	// Construct initial error reporter with fallback icons. Upgraded to a
	// themed reporter once config resolves theme and color.
	fallbackIcons := render.LookupLogIcons("", render.StderrColorEnabled())
	er := newErrReporter(errWriter, fallbackIcons, logLevelOff)

	help, _ := fs.GetBool("help")
	if help {
		writeUsage(fs, stdout)
		return exitSuccess
	}
	versionFlag, _ := fs.GetBool("version")
	if versionFlag {
		writeVersion(version, stdout)
		return exitSuccess
	}

	configPath, _ := fs.GetString("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		er.writeMessage(err.Error())
		return exitConfigError
	}
	// Apply implications before and after CLI overrides:
	// - Before: config-file values like aia_force=true enable aia_fetch
	// - After: CLI flags like --aia-force also trigger aia_fetch
	// The second pass receives fs so it can detect explicit contradictions
	// (e.g., --aia-force --no-aia-fetch) and respect explicit overrides
	// (e.g., --no-verify-hostname with hostname set for SNI).
	_ = applyFlagImplications(cfg, nil)
	applyFlagOverrides(cfg, fs)
	err = applyFlagImplications(cfg, fs)
	if err != nil {
		er.writeMessage(err.Error())
		return exitConfigError
	}

	if err = resolveConfigPaths(cfg); err != nil {
		er.writeMessage(err.Error())
		return exitConfigError
	}

	err = cfg.Validate()
	if err != nil {
		er.writeMessage(err.Error())
		return exitUsageError
	}

	// Validate render/output flag values (--theme, --format, --color,
	// --fields) against the render package's known values. The parsed
	// field names are returned for reuse by buildRenderOptions.
	parsedFields, err := validateFlagValues(cfg)
	if err != nil {
		er.writeMessage(err.Error())
		return exitUsageError
	}

	// Override the fatih/color library's global NoColor flag when the user
	// explicitly requests color output. Must happen before any color
	// functions are invoked (icons, spinner, tree rendering).
	render.OverrideColorLibrary(cfg.Output.Color)

	// Resolve color for themed icons using the same TTY detection as the
	// fallback reporter. "auto" checks stderr TTY state; "always" forces on.
	iconColor := cfg.Output.Color == config.ColorAlways || (cfg.Output.Color == config.ColorAuto && render.StderrColorEnabled())
	icons := render.LookupLogIcons(cfg.Render.Theme, iconColor)
	flags := parseNonConfigFlags(fs)
	flags.parsedFields = parsedFields
	lvl := resolveLogLevel(flags.verboseCount, flags.verboseChanged, cfg.Output.LogLevel)
	er = newErrReporter(errWriter, icons, lvl)

	hasExclusions := flags.hasExclusions()
	positional := fs.Args()
	err = validateSimulationFlags(&flags, cfg.Output.Format)
	if err != nil {
		er.writeMessage(err.Error())
		return exitUsageError
	}

	sources, err := resolveSources(positional, flags.hostsFile)
	if err != nil {
		er.writeMessage(err.Error())
		return exitUsageError
	}
	if len(sources) == 0 {
		writeUsage(fs, errWriter)
		return exitUsageError
	}

	var logger *slog.Logger
	if lvl > logLevelOff {
		logger = newCLILogger(errWriter, lvl, icons)
	} else {
		logger = certree.NewLogger()
	}

	components, err := buildAnalyzer(cfg, logger)
	if err != nil {
		er.writeFormatted(err)
		return exitConfigError
	}
	analyzer := components.analyzer

	// cfg.Validate() guarantees ConnectTimeout is a valid positive duration.
	timeout, _ := time.ParseDuration(cfg.Connection.ConnectTimeout)

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Spinner is disabled when verbose logging is active because log lines and
	// spinner updates both write to stderr, causing interleaved output. Verbose
	// log lines already show progress implicitly, so the spinner adds no value.
	var pw *progressWriter
	if !flags.quiet && lvl == logLevelOff {
		pw = newProgressWriter(errWriter, render.SpinnerFrames(cfg.Render.Theme, cfg.Output.Color != config.ColorNever))
	}
	var analyses []*certree.Analysis
	var sourceEC exitCode
	analyses, sourceEC = analyzeSources(signalCtx, analyzer, sources, timeout, pw, os.Stdin, logger, er)
	if analyses == nil {
		return sourceEC
	}

	hasSimulation := hasExclusions || flags.hasInjections() || flags.validationTime != nil
	if hasSimulation {
		rc := renderSimulation(signalCtx, analyses, flags, cfg, timeout, components, logger, stdout, er)
		return worstExitCode(sourceEC, rc)
	}

	if flags.quiet {
		return worstExitCode(sourceEC, analysesExitCode(analyses))
	}

	return worstExitCode(sourceEC, renderAnalyses(analyses, flags, cfg, stdout, er))
}

// analyzerComponents groups the components built by buildAnalyzer that are
// shared between the primary analysis pipeline and the simulation pipeline.
type analyzerComponents struct {
	analyzer     *certree.Analyzer
	validator    certree.Validator
	chainBuilder certree.ChainBuilder
	trustStore   certree.TrustStore
}

// buildAnalyzer constructs a certree Analyzer from the unified Config.
// The logger is created by Run() and shared with renderSimulation so that
// both analysis and simulation produce consistent verbose output.
func buildAnalyzer(cfg *config.Config, logger *slog.Logger) (*analyzerComponents, error) {
	// cfg.Validate() guarantees FetchTimeout is a valid positive duration.
	fetchTimeout, _ := time.ParseDuration(cfg.Connection.FetchTimeout)
	parserOpts := []certree.ParserOption{
		certree.WithSkipInvalid(cfg.Validation.SkipInvalid),
		certree.WithAutoDetectFormat(true),
		certree.WithMaxCertificates(cfg.Validation.MaxCertificates),
		certree.WithParserAllowPrivateNetworks(cfg.Connection.AllowPrivateNetworks),
		certree.WithURLFetchTimeout(fetchTimeout),
		certree.WithParserLogger(logger),
	}
	p := certree.NewParser(parserOpts...)

	ts := certree.NewTrustStore(
		certree.WithSystemRootsPath(cfg.TrustStore.SystemRoots),
		certree.WithCustomRootsPrecedence(cfg.TrustStore.PreferCustomRoots),
		certree.WithTrustStoreLogger(logger),
	)

	if cfg.TrustStore.TrustBundle != "" {
		if err := ts.LoadCustomRoots(cfg.TrustStore.TrustBundle); err != nil {
			return nil, fmt.Errorf("loading custom trust bundle: %w", err)
		}
	}

	cbOptions := []certree.ChainBuilderOption{
		certree.WithMaxDepth(cfg.Validation.MaxDepth),
		certree.WithAIAFetch(cfg.Connection.AIAFetch),
		certree.WithAIAForce(cfg.Connection.AIAForce),
		certree.WithCircularDetection(true),
		certree.WithChainLogger(logger),
	}
	if cfg.Connection.AIAFetch || cfg.Connection.AIAForce {
		aiaOpts := []certree.AIAFetcherOption{
			certree.WithAIALogger(logger),
			certree.WithAIAAllowPrivateNetworks(cfg.Connection.AllowPrivateNetworks),
		}
		if cfg.Connection.AIATimeout != "" {
			aiaTimeout, err := time.ParseDuration(cfg.Connection.AIATimeout)
			if err != nil {
				return nil, fmt.Errorf("invalid --aia-timeout %q: %w", cfg.Connection.AIATimeout, err)
			}
			aiaOpts = append(aiaOpts, certree.WithAIATimeout(aiaTimeout))
		}
		fetcher := certree.NewAIAFetcher(aiaOpts...)
		cbOptions = append(cbOptions, certree.WithAIAFetcher(fetcher))
	}
	cb := certree.NewChainBuilder(cbOptions...)

	// Construct revocation checker conditionally, mirroring the AIA fetcher
	// pattern: full options (logger) only when revocation checking is
	// enabled, bare constructor otherwise.
	var rc certree.RevocationChecker
	if cfg.Validation.VerifyRevocation {
		rc = certree.NewRevocationChecker(
			certree.WithRevocationLogger(logger),
			certree.WithRevocationAllowPrivateNetworks(cfg.Connection.AllowPrivateNetworks),
		)
	} else {
		rc = certree.NewRevocationChecker()
	}

	v := certree.NewValidator(
		certree.WithValidatorTrustStore(ts),
		certree.WithRevocationChecker(rc),
		certree.WithValidatorLogger(logger),
	)

	valOpts := validationOptionsFromConfig(cfg)

	var remoteOpts *certree.RemoteOptions
	if cfg.Connection.ClientCert != "" && cfg.Connection.ClientKey != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.Connection.ClientCert, cfg.Connection.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		remoteOpts = &certree.RemoteOptions{ClientCert: &clientCert}
	}

	opts := []certree.AnalyzerOption{
		certree.WithParser(p),
		certree.WithTrustStore(ts),
		certree.WithChainBuilder(cb),
		certree.WithValidator(v),
		certree.WithValidationOptions(valOpts),
		certree.WithSNI(cfg.Connection.SNI),
		certree.WithAnalyzerLogger(logger),
	}
	if remoteOpts != nil {
		opts = append(opts, certree.WithRemoteOptions(*remoteOpts))
	}
	analyzer, err := certree.NewAnalyzer(opts...)
	if err != nil {
		return nil, err
	}
	return &analyzerComponents{
		analyzer:     analyzer,
		validator:    v,
		chainBuilder: cb,
		trustStore:   ts,
	}, nil
}

// validationOptionsFromConfig builds ValidationOptions from the analysis
// configuration. Used by both the primary analysis pipeline and the
// simulation pipeline (which may override ValidationTime).
func validationOptionsFromConfig(cfg *config.Config) certree.ValidationOptions {
	return certree.ValidationOptions{
		VerifySignatures:      cfg.Validation.VerifySignatures,
		VerifyExpiry:          cfg.Validation.VerifyExpiry,
		ExpiryWarningDays:     cfg.Validation.ExpiryWarningDays,
		MaxValidityDays:       cfg.Validation.MaxValidityDays,
		VerifyHostname:        cfg.Validation.VerifyHostname,
		Hostname:              cfg.Validation.Hostname,
		VerifyRevocation:      cfg.Validation.VerifyRevocation,
		RevocationFailOpen:    cfg.Validation.RevocationFailOpen,
		VerifyEKU:             cfg.Validation.VerifyEKU,
		VerifyNameConstraints: cfg.Validation.VerifyNameConstraints,
	}
}
