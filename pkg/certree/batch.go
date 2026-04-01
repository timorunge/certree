// Batch processing: concurrent multi-source analysis with worker pool.

package certree

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
)

// Default and hard limits for batch processing.
const (
	defaultBatchWorkers = 4
	maxBatchWorkers     = 8
)

// ProgressFunc is called after each source completes; may be called concurrently.
type ProgressFunc func(completed, total int, source string)

// BatchAnalyzer processes multiple certificate sources concurrently using a worker pool.
type BatchAnalyzer struct {
	maxWorkers int

	analyzer *Analyzer
	logger   *slog.Logger

	onProgress ProgressFunc
	progressMu sync.RWMutex
}

// NewBatchAnalyzer creates a BatchAnalyzer with the given worker limit, clamped to [1, 8].
func NewBatchAnalyzer(analyzer *Analyzer, maxWorkers int) (*BatchAnalyzer, error) {
	if analyzer == nil {
		return nil, NewStructuredError("batch analyzer requires a non-nil analyzer", ErrNilArgument, nil)
	}

	if maxWorkers <= 0 {
		maxWorkers = defaultBatchWorkers
	}

	maxWorkers = max(1, min(maxWorkers, maxBatchWorkers))

	logger := NewLogger()
	if analyzer.logger != nil {
		logger = analyzer.logger
	}

	return &BatchAnalyzer{
		analyzer:   analyzer,
		maxWorkers: maxWorkers,
		logger:     logger,
	}, nil
}

// SetProgress registers a progress callback, safe to call concurrently.
func (ba *BatchAnalyzer) SetProgress(fn ProgressFunc) {
	ba.progressMu.Lock()
	ba.onProgress = fn
	ba.progressMu.Unlock()
}

// AnalyzeMultiple processes sources concurrently and returns successful results
// in input order. The joined error preserves [*StructuredError] per failed source,
// extractable via Unwrap() []error and [errors.As].
func (ba *BatchAnalyzer) AnalyzeMultiple(ctx context.Context, sources []string) ([]*Analysis, error) {
	if len(sources) == 0 {
		return nil, NewStructuredError(
			"no sources provided for batch analysis",
			ErrEmptyInput,
			nil,
		)
	}

	total := len(sources)
	ba.logger.Info("starting batch analysis", "sources", total, "workers", ba.maxWorkers)

	type batchJob struct {
		source string
		index  int
	}

	jobs := make(chan batchJob, total)
	results := make(chan analysisResult, total)

	var completed atomic.Int64
	var wg sync.WaitGroup
	for i := range ba.maxWorkers {
		workerID := i
		wg.Go(func() {
			for job := range jobs {
				select {
				case <-ctx.Done():
					results <- analysisResult{source: job.source, sourceIndex: job.index, err: ctx.Err()}
					ba.reportProgress(int(completed.Add(1)), total, job.source)
					continue
				default:
				}
				ba.logger.Debug("worker processing source", "worker", workerID, "source", job.source)
				analysis, err := ba.analyzer.Analyze(ctx, job.source)
				results <- analysisResult{source: job.source, sourceIndex: job.index, analysis: analysis, err: err}
				if err != nil {
					ba.logger.Warn("worker failed", "worker", workerID, "source", job.source, "error", err)
				}
				ba.reportProgress(int(completed.Add(1)), total, job.source)
			}
		})
	}

	for i, source := range sources {
		jobs <- batchJob{source: source, index: i}
	}
	close(jobs)

	wg.Wait()
	close(results)

	type indexedAnalysis struct {
		idx      int
		analysis *Analysis
	}

	indexed := make([]indexedAnalysis, 0, len(sources))
	var errs []error
	for r := range results {
		if r.err != nil {
			// Wrap with source identifier for errors.Join grouping.
			// This is intentionally fmt.Errorf because the source label
			// is a batch grouping key, not structured data. The inner
			// error may be a *StructuredError from the analyzer,
			// extractable via errors.As through this wrapping.
			errs = append(errs, fmt.Errorf("%s: %w", r.source, r.err))
			continue
		}
		indexed = append(indexed, indexedAnalysis{idx: r.sourceIndex, analysis: r.analysis})
	}

	// Sort results by original input order for deterministic output.
	// Using the per-result sourceIndex avoids clobbering with duplicate source strings.
	slices.SortFunc(indexed, func(a, b indexedAnalysis) int {
		return cmp.Compare(a.idx, b.idx)
	})

	analyses := make([]*Analysis, len(indexed))
	for i, ia := range indexed {
		analyses[i] = ia.analysis
	}

	ba.logger.Info("batch analysis complete", "total", len(analyses), "errors", len(errs))

	if len(errs) > 0 {
		return analyses, errors.Join(errs...)
	}
	return analyses, nil
}

// reportProgress invokes the registered progress callback, if any.
func (ba *BatchAnalyzer) reportProgress(completed, total int, source string) {
	ba.progressMu.RLock()
	fn := ba.onProgress
	ba.progressMu.RUnlock()
	if fn != nil {
		fn(completed, total, source)
	}
}

// analysisResult pairs a source with its analysis outcome for result collection.
type analysisResult struct {
	source      string
	sourceIndex int // original position for deterministic ordering
	analysis    *Analysis
	err         error
}
