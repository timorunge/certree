// Source resolution, file loading, validation, and analysis dispatch.

package cli

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/timorunge/certree/pkg/certree"
)

const (
	maxBatchTimeout     = 10 * time.Minute
	maxSourceLineLength = 4096
	maxSourceFileSize   = 10 << 20 // 10 MB

	// forbiddenSourceChars contains shell metacharacters and control characters
	// rejected in batch file lines to prevent command injection.
	forbiddenSourceChars = ";|&<>$`\n\r\x00"
)

// resolveSources merges positional sources with batch file sources.
// Positional sources come first, followed by batch sources. Returns an error
// on invalid sources, unreadable batch files, or duplicate stdin.
func resolveSources(positional []string, hostsFile string) ([]string, error) {
	combined := slices.Clone(positional)

	for _, src := range combined {
		if err := certree.ValidateSource(src); err != nil {
			return nil, err
		}
	}

	if hostsFile != "" {
		batchSources, err := loadSourcesFromFile(hostsFile)
		if err != nil {
			return nil, fmt.Errorf("loading batch sources from %s: %w", hostsFile, err)
		}
		combined = append(combined, batchSources...)
	}

	stdinCount := 0
	for _, s := range combined {
		if s == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return nil, fmt.Errorf("stdin (-) can only be specified once")
	}
	if stdinCount > 0 && len(combined) > 1 {
		return nil, fmt.Errorf("stdin (-) cannot be combined with other sources")
	}

	if len(combined) == 0 && hostsFile != "" {
		return nil, fmt.Errorf("batch file %q contained no valid sources", hostsFile)
	}

	combined = deduplicateSources(combined)

	return combined, nil
}

// analyzeSources dispatches to single or batch analysis based on source count.
func analyzeSources(
	ctx context.Context,
	analyzer *certree.Analyzer,
	sources []string,
	timeout time.Duration,
	pw *progressWriter,
	stdin io.Reader,
	logger *slog.Logger,
	er *errReporter,
) ([]*certree.Analysis, exitCode) {
	if len(sources) == 1 {
		return analyzeSingle(ctx, analyzer, sources[0], timeout, stdin, logger, er)
	}
	return analyzeBatch(ctx, analyzer, sources, timeout, pw, logger, er)
}

// analyzeSingle analyzes one source, handling stdin, file, host, and URL types.
func analyzeSingle(
	ctx context.Context,
	analyzer *certree.Analyzer,
	source string,
	timeout time.Duration,
	stdin io.Reader,
	logger *slog.Logger,
	er *errReporter,
) ([]*certree.Analysis, exitCode) {
	if source == "-" {
		analysis, ec, err := analyzeStdin(ctx, analyzer, timeout, stdin)
		if err != nil {
			er.writeFormatted(err)
			return nil, ec
		}
		return []*certree.Analysis{analysis}, exitSuccess
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	kind := certree.DetectSource(source)
	normalized := certree.NormalizeSource(source)
	if normalized != source {
		logger.Debug("normalized source", "original", source, "normalized", normalized)
	}

	var analysis *certree.Analysis
	var err error
	var ec exitCode

	switch kind {
	case certree.SourceURL:
		analysis, err = analyzer.AnalyzeURL(ctx, normalized)
		ec = exitConnectionError
	case certree.SourceHost:
		analysis, err = analyzer.AnalyzeHost(ctx, normalized)
		ec = exitConnectionError
	default:
		analysis, err = analyzer.AnalyzeFile(ctx, source)
		ec = exitParseError
		if errors.Is(err, certree.ErrFileReadFailed) || errors.Is(err, certree.ErrFileTooLarge) {
			ec = exitUsageError
		}
	}

	if err != nil {
		er.writeFormatted(err)
		return nil, ec
	}
	// Show the original CLI source for display when the user omitted the
	// scheme, so "i.pki.goog/r1.pem" is shown instead of "https://...".
	if kind != certree.SourceURL {
		analysis = certree.NewAnalysis(analysis.Certificates, analysis.TrustPaths, source,
			certree.WithSimulated(analysis.Metadata.IsSimulated))
	}
	return []*certree.Analysis{analysis}, exitSuccess
}

// analyzeBatch normalizes and processes multiple sources concurrently via
// certree.BatchAnalyzer, preserving the original command-line order.
func analyzeBatch(
	ctx context.Context,
	analyzer *certree.Analyzer,
	sources []string,
	timeout time.Duration,
	pw *progressWriter,
	logger *slog.Logger,
	er *errReporter,
) ([]*certree.Analysis, exitCode) {
	normalized := make([]string, len(sources))
	originalSource := make(map[string]string, len(sources))
	for i, src := range sources {
		normalized[i] = certree.NormalizeSource(src)
		if normalized[i] != src {
			logger.Debug("normalized source", "original", src, "normalized", normalized[i])
		}
		if _, exists := originalSource[normalized[i]]; !exists {
			originalSource[normalized[i]] = src
		}
	}

	// Cap batch timeout to avoid int64 overflow with large source counts.
	batchTimeout := maxBatchTimeout
	n := len(normalized)
	if n > 0 && timeout > 0 && n <= int(maxBatchTimeout/timeout) {
		batchTimeout = timeout * time.Duration(n)
	}
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()

	ba, err := certree.NewBatchAnalyzer(analyzer, n)
	if err != nil {
		er.writeMessage(err.Error())
		return nil, exitParseError
	}
	if pw != nil {
		ba.SetProgress(pw.progressFunc())
	}
	analyses, batchErr := ba.AnalyzeMultiple(ctx, normalized)
	if pw != nil {
		pw.Done()
	}
	var ec exitCode
	if batchErr != nil {
		er.writeFormatted(batchErr)
		if len(analyses) == 0 {
			return nil, exitConnectionError
		}
		ec = exitConnectionError
	}

	// sourceOrder is keyed on normalized sources which are passed verbatim
	// to AnalyzeMultiple; Analyze stores the source string unchanged in
	// Analysis.Metadata.Source, so every analysis maps to a known key.
	sourceOrder := make(map[string]int, n)
	for i, src := range normalized {
		if _, exists := sourceOrder[src]; !exists {
			sourceOrder[src] = i
		}
	}
	slices.SortStableFunc(analyses, func(a, b *certree.Analysis) int {
		return cmp.Compare(sourceOrder[a.Metadata.Source], sourceOrder[b.Metadata.Source])
	})

	for i, a := range analyses {
		if orig, ok := originalSource[a.Metadata.Source]; ok && certree.DetectSource(orig) != certree.SourceURL {
			analyses[i] = certree.NewAnalysis(a.Certificates, a.TrustPaths, orig,
				certree.WithSimulated(a.Metadata.IsSimulated))
		}
	}

	return analyses, ec
}

// analyzeStdin reads certificate data from stdin and analyzes it. The select
// respects ctx cancellation, but the io.ReadAll goroutine may outlive the
// context.
func analyzeStdin(ctx context.Context, analyzer *certree.Analyzer, timeout time.Duration, stdin io.Reader) (*certree.Analysis, exitCode, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		// Limit stdin reads to prevent unbounded memory allocation from
		// malicious or accidental piping of large data (e.g., /dev/zero).
		// AnalyzeBytes also enforces this limit, but capping here avoids
		// the allocation entirely.
		const maxStdinSize = 10 << 20 // 10 MB, matches parser.maxParserInputSize.
		data, err := io.ReadAll(io.LimitReader(stdin, int64(maxStdinSize)+1))
		if err == nil && len(data) > maxStdinSize {
			err = fmt.Errorf("stdin input exceeds size limit (%d bytes)", maxStdinSize)
		}
		ch <- readResult{data, err}
	}()

	var data []byte
	select {
	case <-ctx.Done():
		return nil, exitParseError, fmt.Errorf("reading stdin: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, exitParseError, fmt.Errorf("reading stdin: %w", res.err)
		}
		data = res.data
	}

	if len(data) == 0 {
		return nil, exitUsageError, fmt.Errorf("no data on stdin")
	}

	analysis, err := analyzer.AnalyzeBytes(ctx, data, "stdin")
	if err != nil {
		return nil, exitParseError, fmt.Errorf("analyzing stdin: %w", err)
	}
	return analysis, exitSuccess, nil
}

// loadSourcesFromFile reads sources from a file, one per line. Empty lines
// and #-prefixed comment lines are skipped. If the first non-comment entry
// is invalid, the whole file is rejected with a file-level error.
func loadSourcesFromFile(path string) (sources []string, retErr error) {
	// #nosec G304 G703 -- File path comes from user-supplied CLI argument
	file, err := os.Open(path)
	if err != nil {
		return nil, certree.NewStructuredError(
			fmt.Sprintf("could not open sources file %s", path),
			certree.ErrFileReadFailed, err,
		)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && retErr == nil {
			retErr = certree.NewStructuredError(
				fmt.Sprintf("could not close sources file %s", path),
				certree.ErrFileReadFailed, closeErr,
			)
		}
	}()

	fi, err := file.Stat()
	if err != nil {
		return nil, certree.NewStructuredError(
			fmt.Sprintf("could not stat sources file %s", path),
			certree.ErrFileReadFailed, err,
		)
	}
	if fi.Size() > int64(maxSourceFileSize) {
		return nil, certree.NewStructuredError(
			fmt.Sprintf("sources file %s exceeds size limit (%d bytes)", path, maxSourceFileSize),
			certree.ErrFileTooLarge, nil,
		)
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, maxSourceLineLength), maxSourceLineLength)
	lineNum := 0
	firstEntry := true

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if err := validateBatchLine(line); err != nil {
			return nil, batchLineError(path, lineNum, firstEntry, err)
		}

		if err := certree.ValidateSource(line); err != nil {
			return nil, batchLineError(path, lineNum, firstEntry, err)
		}

		firstEntry = false
		sources = append(sources, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, certree.NewStructuredError(
			fmt.Sprintf("could not read sources file %s", path),
			certree.ErrFileReadFailed, err,
		)
	}

	return sources, nil
}

// batchLineError returns a file-level error when the first entry is invalid,
// or a line-level error for subsequent entries.
func batchLineError(path string, lineNum int, firstEntry bool, cause error) error {
	msg := fmt.Sprintf("invalid source at line %d in %s: %s", lineNum, path, cause.Error())
	if firstEntry {
		msg = fmt.Sprintf("%s does not appear to be a valid sources file", path)
	}
	return certree.NewStructuredError(msg, certree.ErrInvalidInput, cause)
}

// validateBatchLine rejects shell metacharacters, path traversal, and
// overly long inputs in batch file lines.
func validateBatchLine(line string) error {
	if strings.ContainsAny(line, forbiddenSourceChars) {
		return fmt.Errorf("source contains forbidden characters: %w", certree.ErrInvalidInput)
	}
	// ".." is valid in URL paths; only check local sources.
	if certree.DetectSource(line) != certree.SourceURL && containsPathTraversal(line) {
		return fmt.Errorf("source contains path traversal: %w", certree.ErrInvalidInput)
	}
	return nil
}

// deduplicateSources removes duplicate entries from sources while preserving
// order. The first occurrence of each source is kept.
func deduplicateSources(sources []string) []string {
	seen := make(map[string]struct{}, len(sources))
	result := make([]string, 0, len(sources))
	for _, s := range sources {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// containsPathTraversal reports whether s contains a ".." path component.
func containsPathTraversal(s string) bool {
	normalized := strings.ReplaceAll(s, "\\", "/")
	return slices.Contains(strings.Split(normalized, "/"), "..")
}
