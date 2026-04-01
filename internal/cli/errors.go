// Structured error formatting with verbosity-dependent detail levels.

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

// errReporter writes themed error messages to stderr. It encapsulates the
// writer, icons, and log level so callers do not need to thread these
// values through every function signature.
type errReporter struct {
	w     io.Writer
	icons render.LogIcons
	level logLevel
}

// newErrReporter creates an error reporter with the given icons and log
// level. For early CLI errors (before config/theme resolution), pass
// fallback icons from render.LookupLogIcons("", false) and logLevelOff.
// After theme validation, construct a new reporter with themed icons and
// the resolved log level.
func newErrReporter(w io.Writer, icons render.LogIcons, level logLevel) *errReporter {
	return &errReporter{
		w:     w,
		icons: icons,
		level: level,
	}
}

// writeMessage writes a single-line human-readable message prefixed with the
// themed error icon. Use this for CLI-layer messages (flag errors, config
// failures, render errors) where the message text is already user-friendly.
// For errors from pkg/certree that may contain a StructuredError, use
// writeFormatted instead.
func (r *errReporter) writeMessage(msg string) {
	_, _ = fmt.Fprintf(r.w, "%s %s\n", r.icons.Error, msg)
}

// writeFormatted writes a formatted error with verbosity-appropriate detail.
// It handles both single errors and batch errors (from errors.Join) by
// checking for the Unwrap() []error interface. Each inner error is formatted
// independently with its own error icon prefix and detail continuation lines.
func (r *errReporter) writeFormatted(err error) {
	if err == nil {
		return
	}

	type unwrapMulti interface{ Unwrap() []error }

	if multi, ok := err.(unwrapMulti); ok {
		for _, e := range multi.Unwrap() {
			if e != nil {
				r.writeParts(formatErrorParts(e))
			}
		}
		return
	}

	r.writeParts(formatErrorParts(err))
}

// writeParts writes a formattedError to the writer. The primary message is
// always shown with the error icon. Additional fields are rendered as
// detail-icon-prefixed continuation lines when verbose logging is active
// (logLevelInfo or higher, matching the -vvv flag threshold):
//   - logLevelOff/logLevelError/logLevelWarn: message only (clean, actionable)
//   - logLevelInfo+: message + Detail + Category (full diagnostic)
func (r *errReporter) writeParts(fe formattedError) {
	_, _ = fmt.Fprintf(r.w, "%s %s\n", r.icons.Error, fe.message)
	if r.level >= logLevelInfo {
		if fe.detail != "" {
			_, _ = fmt.Fprintf(r.w, "%s Detail: %s\n", r.icons.Continuation, fe.detail)
		}
		if fe.category != "" {
			_, _ = fmt.Fprintf(r.w, "%s Category: %s\n", r.icons.Continuation, fe.category)
		}
	}
}

// formattedError holds the structured parts of a CLI error message after
// extraction. Each field is populated independently of verbosity; the
// presenter (writeParts) decides which fields to render based on the
// current verbosity level.
//
// The three fields -- message, detail, and category -- are separate concerns
// extracted from a StructuredError. For plain errors, only message is set.
type formattedError struct {
	message  string // primary user-facing message (always present)
	detail   string // raw error for debugging (empty when no cause)
	category string // sentinel category for programmatic matching (empty when no category)
}

// formatErrorParts extracts all structured parts from an error. If the
// error contains a StructuredError, it extracts the user message, raw
// detail, and sentinel category. When the StructuredError is wrapped in
// fmt.Errorf with additional context (e.g., "simulation failed for X: ..."),
// the wrapper context is preserved in the message so it is visible even
// at verbosity 0.
//
// This function is a pure data extractor: it populates all available
// fields regardless of verbosity. The presenter (writeParts) applies
// verbosity filtering during rendering.
func formatErrorParts(err error) formattedError {
	if err == nil {
		return formattedError{}
	}

	se, ok := errors.AsType[*certree.StructuredError](err)
	if !ok {
		return formattedError{message: err.Error()}
	}

	// When a StructuredError is wrapped in fmt.Errorf (e.g.,
	// "parsing inject file X: <se.Error()>"), the outer error's
	// text contains context that se.UserMessage() alone would lose.
	msg := se.UserMessage()
	if outer := err.Error(); outer != se.Error() {
		msg = outer
	}

	fe := formattedError{message: msg}

	if detail := se.Detail(); detail != nil {
		fe.detail = detail.Error()
	}
	if cat := se.Category(); cat != nil {
		fe.category = cat.Error()
	}

	return fe
}
