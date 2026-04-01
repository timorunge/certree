// Output orchestration: JSON formatting, tree/comparison/diff dispatch, and simulation pipeline.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/timorunge/certree/internal/config"
	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

// buildRenderOptions constructs render.Options from the Config and runtime flags.
// The parsedFields slice must come from a prior parseFields call (done during
// validation), eliminating redundant re-parsing on every render.
func buildRenderOptions(cfg *config.Config, flags nonConfigFlags) render.Options {
	opts := render.Options{
		ThemeName:         cfg.Render.Theme,
		ColorMode:         cfg.Output.Color,
		ReverseOrder:      cfg.Render.Reverse,
		ShowAnnotations:   cfg.Render.Annotations,
		ExpiryWarningDays: cfg.Validation.ExpiryWarningDays,
		ShowPathIndex:     cfg.Render.PathIndex,
		ExpandedView:      cfg.Render.Expand,
		WrapLines:         cfg.Render.Wrap,
	}
	applyParsedFields(&opts, flags.parsedFields)
	return opts
}

// renderJSON marshals v as indented JSON and writes it to w.
func renderJSON(v any, w io.Writer) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing to JSON: %w", err)
	}
	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("writing JSON output: %w", err)
	}
	_, err = io.WriteString(w, "\n")
	if err != nil {
		return fmt.Errorf("writing JSON trailing newline: %w", err)
	}
	return nil
}

// analysisPairs zips originals and simulated slices into AnalysisPair slice.
// Both slices must have equal length; if they differ, the shorter length is used.
func analysisPairs(originals, simulated []*certree.Analysis) []render.AnalysisPair {
	n := min(len(originals), len(simulated))
	pairs := make([]render.AnalysisPair, n)
	for i, orig := range originals[:n] {
		pairs[i] = render.AnalysisPair{Before: orig, After: simulated[i]} // #nosec G602 -- i < n <= len(simulated)
	}
	return pairs
}

// renderAnalyses renders one or more analyses to the writer, returning an
// exit code. For JSON format it always serializes to a JSON array, even for a
// single source, so consumers can rely on a consistent type. For tree format
// it renders all analyses via render.Trees.
func renderAnalyses(
	analyses []*certree.Analysis,
	flags nonConfigFlags,
	cfg *config.Config,
	w io.Writer,
	er *errReporter,
) exitCode {
	analyses = filterAnalyses(analyses, flags)

	if cfg.Output.Format == config.FormatJSON {
		jsonAnalyses := analyses
		if cfg.Render.Reverse {
			jsonAnalyses = make([]*certree.Analysis, len(analyses))
			for i, a := range analyses {
				jsonAnalyses[i] = a.Reversed()
			}
		}
		if err := renderJSON(jsonAnalyses, w); err != nil {
			er.writeMessage(err.Error())
			return exitRenderError
		}
		return analysesExitCode(analyses)
	}

	opts := buildRenderOptions(cfg, flags)
	if err := render.Trees(analyses, opts, w); err != nil {
		er.writeMessage(err.Error())
		return exitRenderError
	}
	return analysesExitCode(analyses)
}

// renderComparison renders before/after simulation pairs. For JSON format it
// outputs [{before, after}] objects; for tree format it delegates to
// render.Comparisons.
func renderComparison(
	originals, simulated []*certree.Analysis,
	flags nonConfigFlags,
	cfg *config.Config,
	w io.Writer,
	er *errReporter,
) exitCode {
	// Exit code uses unfiltered data so filters do not mask validation failures.
	unfilteredSimulated := simulated
	originals = filterAnalyses(originals, flags)
	simulated = filterAnalyses(simulated, flags)

	if cfg.Output.Format == config.FormatJSON {
		type jsonPair struct {
			Before *certree.Analysis `json:"before"`
			After  *certree.Analysis `json:"after"`
		}
		n := min(len(originals), len(simulated))
		pairs := make([]jsonPair, n)
		for i := range n {
			b, a := originals[i], simulated[i]
			if cfg.Render.Reverse {
				b = b.Reversed()
				a = a.Reversed()
			}
			pairs[i] = jsonPair{Before: b, After: a}
		}
		if err := renderJSON(pairs, w); err != nil {
			er.writeMessage(err.Error())
			return exitRenderError
		}
		return analysesExitCode(unfilteredSimulated)
	}

	pairs := analysisPairs(originals, simulated)
	opts := buildRenderOptions(cfg, flags)
	opts.Impact = flags.impact

	if err := render.Comparisons(pairs, opts, w); err != nil {
		er.writeMessage(err.Error())
		return exitRenderError
	}
	return analysesExitCode(unfilteredSimulated)
}

// renderDiff renders before/after simulation pairs as a unified diff. JSON
// format is blocked by run() validation, so only tree format is handled.
func renderDiff(
	originals, simulated []*certree.Analysis,
	flags nonConfigFlags,
	cfg *config.Config,
	w io.Writer,
	er *errReporter,
) exitCode {
	// Exit code uses unfiltered data so filters do not mask validation failures.
	unfilteredSimulated := simulated
	originals = filterAnalyses(originals, flags)
	simulated = filterAnalyses(simulated, flags)

	pairs := analysisPairs(originals, simulated)
	sources := make([]string, len(originals))
	for i := range originals {
		sources[i] = originals[i].Metadata.Source
	}

	opts := buildRenderOptions(cfg, flags)
	opts.Impact = flags.impact

	if err := render.Diffs(pairs, sources, opts, w); err != nil {
		er.writeMessage(err.Error())
		return exitRenderError
	}
	return analysesExitCode(unfilteredSimulated)
}

// buildSimulator constructs and configures a Simulator from CLI flags and config.
// Returns the simulator and an exit code; a non-zero exit code means an error
// was already reported via er and the caller should return immediately.
func buildSimulator(
	ctx context.Context,
	flags nonConfigFlags,
	cfg *config.Config,
	timeout time.Duration,
	ac *analyzerComponents,
	logger *slog.Logger,
	er *errReporter,
) (certree.Simulator, exitCode) {
	simOpts := []certree.SimulatorOption{certree.WithSimulatorLogger(logger)}

	if flags.validationTime != nil {
		vt := *flags.validationTime
		shiftedOpts := validationOptionsFromConfig(cfg)
		shiftedOpts.ValidationTime = vt

		// Build a time-shifted validator so revocation freshness checks
		// also use the shifted time, not just expiry checks.
		simValidator := ac.validator
		if cfg.Validation.VerifyRevocation {
			rc := certree.NewRevocationChecker(
				certree.WithRevocationLogger(logger),
				certree.WithRevocationAllowPrivateNetworks(cfg.Connection.AllowPrivateNetworks),
				certree.WithRevocationValidationTime(vt),
			)
			simValidator = certree.NewValidator(
				certree.WithValidatorTrustStore(ac.trustStore),
				certree.WithRevocationChecker(rc),
				certree.WithValidatorLogger(logger),
			)
		}
		simOpts = append(simOpts,
			certree.WithSimulatorValidator(simValidator),
			certree.WithSimulatorValidationOptions(shiftedOpts),
		)
	}

	hasInj := flags.hasInjections()
	if hasInj {
		simOpts = append(simOpts,
			certree.WithSimulatorChainBuilder(ac.chainBuilder),
			certree.WithSimulatorTrustStore(ac.trustStore),
		)
	}

	sim := certree.NewSimulator(simOpts...)
	for _, cn := range flags.excludeCN {
		sim.ExcludeByCommonName(cn)
	}
	for _, fp := range flags.excludeFingerprint {
		sim.ExcludeByFingerprint(fp)
	}
	for _, serial := range flags.excludeSerial {
		sim.ExcludeBySerial(serial)
	}
	if hasInj {
		injParser := certree.NewParser(
			certree.WithSkipInvalid(cfg.Validation.SkipInvalid),
			certree.WithAutoDetectFormat(true),
			certree.WithMaxCertificates(cfg.Validation.MaxCertificates),
			certree.WithParserLogger(logger),
		)
		for _, path := range flags.injectFiles {
			if containsPathTraversal(path) {
				er.writeFormatted(fmt.Errorf("inject path %q contains path traversal: %w", path, certree.ErrInvalidInput))
				return nil, exitUsageError
			}
			injCtx, cancel := context.WithTimeout(ctx, timeout)
			certs, parseErr := injParser.ParseFile(injCtx, path)
			cancel()
			if parseErr != nil {
				er.writeFormatted(fmt.Errorf("parsing inject file %s: %w", path, parseErr))
				return nil, exitParseError
			}
			sim.InjectCertificates(certs)
		}
	}

	return sim, exitSuccess
}

// renderSimulation runs simulation with exclusion/injection flags and renders
// the result. It delegates to renderComparison, renderDiff, or renderAnalyses
// depending on the flags.
func renderSimulation(
	ctx context.Context,
	analyses []*certree.Analysis,
	flags nonConfigFlags,
	cfg *config.Config,
	timeout time.Duration,
	ac *analyzerComponents,
	logger *slog.Logger,
	w io.Writer,
	er *errReporter,
) exitCode {
	sim, code := buildSimulator(ctx, flags, cfg, timeout, ac, logger, er)
	if code != exitSuccess {
		return code
	}

	originals := analyses
	simulated := make([]*certree.Analysis, len(analyses))
	for i, original := range originals {
		simCtx, cancel := context.WithTimeout(ctx, timeout)
		s, err := sim.Simulate(simCtx, original)
		cancel()
		if err != nil {
			er.writeFormatted(fmt.Errorf("simulation failed for %s: %w", render.SanitizeCertString(original.Metadata.Source), err))
			return exitValidationError
		}
		simulated[i] = s
	}

	if flags.hasExclusions() {
		warnUnmatchedExclusions(originals, simulated, er)
	}

	if flags.quiet {
		return analysesExitCode(simulated)
	}

	if flags.compare {
		return renderComparison(originals, simulated, flags, cfg, w, er)
	}

	if flags.diff {
		return renderDiff(originals, simulated, flags, cfg, w, er)
	}

	// Impact summary and exit code use unfiltered data so CN filtering
	// does not mask the true impact of exclusions.
	unfilteredSimulated := simulated
	simulated = filterAnalyses(simulated, flags)
	opts := buildRenderOptions(cfg, flags)

	if cfg.Output.Format == config.FormatJSON {
		jsonSimulated := simulated
		if cfg.Render.Reverse {
			jsonSimulated = make([]*certree.Analysis, len(simulated))
			for i, s := range simulated {
				jsonSimulated[i] = s.Reversed()
			}
		}
		if err := renderJSON(jsonSimulated, w); err != nil {
			er.writeMessage(err.Error())
			return exitRenderError
		}
		return analysesExitCode(unfilteredSimulated)
	}

	if !flags.impact {
		if err := render.Trees(simulated, opts, w); err != nil {
			er.writeMessage(err.Error())
			return exitRenderError
		}
		return analysesExitCode(unfilteredSimulated)
	}

	for i, s := range simulated {
		if err := render.Trees([]*certree.Analysis{s}, opts, w); err != nil {
			er.writeMessage(err.Error())
			return exitRenderError
		}
		summary := render.ImpactSummary(originals[i], unfilteredSimulated[i], render.SectionIndent(cfg.Render.Theme), render.LabelSep(cfg.Render.Theme), cfg.Validation.ExpiryWarningDays)
		_, _ = fmt.Fprint(w, "\n")
		_, _ = io.WriteString(w, summary)
	}

	return analysesExitCode(unfilteredSimulated)
}

// warnUnmatchedExclusions emits a warning when exclusion patterns did not
// match any certificates. Compares certificate counts between original and
// simulated analyses to detect no-ops.
func warnUnmatchedExclusions(originals, simulated []*certree.Analysis, er *errReporter) {
	for i, orig := range originals {
		if i >= len(simulated) {
			break
		}
		if !simulationChangedAnalysis(orig, simulated[i]) {
			er.writeMessage(fmt.Sprintf("warning: exclusion patterns did not match any certificates in %s", render.SanitizeCertString(orig.Metadata.Source)))
		}
	}
}

// simulationChangedAnalysis reports whether the simulation produced any
// observable change: either paths were removed (leaf excluded) or
// certificates were marked as excluded in remaining paths.
func simulationChangedAnalysis(orig, sim *certree.Analysis) bool {
	if len(sim.TrustPaths) != len(orig.TrustPaths) {
		return true
	}
	for _, tp := range sim.TrustPaths {
		for _, state := range tp.SimulationMetadata {
			if state.IsExcluded {
				return true
			}
		}
	}
	return false
}
