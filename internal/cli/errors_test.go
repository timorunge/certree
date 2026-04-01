package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

// assertFormattedError checks that a formattedError matches the expected
// values for all fields. It marks the calling test as a helper.
func assertFormattedError(t *testing.T, got, want formattedError) {
	t.Helper()

	if got.message != want.message {
		t.Errorf("message = %q, want %q", got.message, want.message)
	}
	if got.detail != want.detail {
		t.Errorf("detail = %q, want %q", got.detail, want.detail)
	}
	if got.category != want.category {
		t.Errorf("category = %q, want %q", got.category, want.category)
	}
}

func TestFormatErrorParts_NonStructuredError(t *testing.T) {
	t.Parallel()

	plainErr := errors.New("invalid configuration: unknown field")

	fe := formatErrorParts(plainErr)
	assertFormattedError(t, fe, formattedError{
		message: "invalid configuration: unknown field",
	})
}

func TestFormatErrorParts_NilError(t *testing.T) {
	t.Parallel()

	fe := formatErrorParts(nil)
	assertFormattedError(t, fe, formattedError{})
}

func TestFormatErrorParts_NewSentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want formattedError
	}{
		{
			name: "connection failure with cause",
			err: certree.NewStructuredError(
				"could not connect to blaaaaa.de:443",
				certree.ErrConnectionFailed,
				errors.New("dial tcp: lookup blaaaaa.de on 192.168.178.4:53: no such host"),
			),
			want: formattedError{
				message:  "could not connect to blaaaaa.de:443",
				detail:   "dial tcp: lookup blaaaaa.de on 192.168.178.4:53: no such host",
				category: "certree: connection failed",
			},
		},
		{
			name: "nil cause omits detail",
			err:  certree.NewStructuredError("no certificates found", certree.ErrNoCertificatesFound, nil),
			want: formattedError{
				message:  "no certificates found",
				category: "certree: no certificates found",
			},
		},
		{
			name: "chain build failed",
			err:  certree.NewStructuredError("operation failed", certree.ErrChainBuildFailed, errors.New("cause")),
			want: formattedError{
				message:  "operation failed",
				detail:   "cause",
				category: "certree: chain build failed",
			},
		},
		{
			name: "validation failed",
			err:  certree.NewStructuredError("operation failed", certree.ErrValidationFailed, errors.New("cause")),
			want: formattedError{
				message:  "operation failed",
				detail:   "cause",
				category: "certree: validation failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fe := formatErrorParts(tt.err)
			assertFormattedError(t, fe, tt.want)
		})
	}
}

func TestErrReporter_WriteMessage(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	er := &errReporter{w: &buf, icons: render.LogIcons{Error: "[x ]"}}

	er.writeMessage("something went wrong")
	got := buf.String()
	want := "[x ] something went wrong\n"
	if got != want {
		t.Errorf("writeMessage() = %q, want %q", got, want)
	}
}

func TestErrReporter_WriteFormattedNil(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	er := &errReporter{
		w:     &buf,
		icons: render.LogIcons{Error: "[x ]", Continuation: "[. ]"},
		level: logLevelDebug,
	}
	er.writeFormatted(nil)
	if buf.Len() != 0 {
		t.Errorf("writeFormatted(nil) produced output %q, want empty", buf.String())
	}
}

func TestErrReporter_WriteFormatted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		err   error
		level logLevel
		want  string
	}{
		{
			name:  "structured error level off",
			err:   certree.NewStructuredError("could not connect", certree.ErrConnectionFailed, errors.New("dial error")),
			level: logLevelOff,
			want:  "[x ] could not connect\n",
		},
		{
			name:  "structured error level info with detail and category",
			err:   certree.NewStructuredError("could not connect", certree.ErrConnectionFailed, errors.New("dial error")),
			level: logLevelInfo,
			want:  "[x ] could not connect\n[. ] Detail: dial error\n[. ] Category: certree: connection failed\n",
		},
		{
			name:  "nil cause at off level",
			err:   certree.NewStructuredError("no certificates found", certree.ErrNoCertificatesFound, nil),
			level: logLevelOff,
			want:  "[x ] no certificates found\n",
		},
		{
			name:  "nil cause at info level",
			err:   certree.NewStructuredError("no certificates found", certree.ErrNoCertificatesFound, nil),
			level: logLevelInfo,
			want:  "[x ] no certificates found\n[. ] Category: certree: no certificates found\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf strings.Builder
			er := &errReporter{
				w:     &buf,
				icons: render.LogIcons{Error: "[x ]", Continuation: "[. ]"},
				level: tt.level,
			}
			er.writeFormatted(tt.err)
			got := buf.String()
			if got != tt.want {
				t.Errorf("writeFormatted() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrReporter_WriteFormattedBatch(t *testing.T) {
	t.Parallel()

	se1 := certree.NewStructuredError("could not connect to a.com:443", certree.ErrConnectionFailed, errors.New("dial 1"))
	se2 := certree.NewStructuredError("could not connect to b.com:443", certree.ErrConnectionFailed, errors.New("dial 2"))
	batchErr := errors.Join(
		fmt.Errorf("a.com:443: %w", se1),
		fmt.Errorf("b.com:443: %w", se2),
	)

	tests := []struct {
		name   string
		level  logLevel
		checks func(t *testing.T, got string)
	}{
		{
			name:  "level off messages only",
			level: logLevelOff,
			checks: func(t *testing.T, got string) {
				t.Helper()
				if !strings.Contains(got, "could not connect to a.com:443") {
					t.Errorf("output should contain first user message, got %q", got)
				}
				if !strings.Contains(got, "could not connect to b.com:443") {
					t.Errorf("output should contain second user message, got %q", got)
				}
				if strings.Contains(got, "Detail:") {
					t.Errorf("output should NOT contain Detail at v0, got %q", got)
				}
				if strings.Contains(got, "Category:") {
					t.Errorf("output should NOT contain Category at v0, got %q", got)
				}
			},
		},
		{
			name:  "level info with detail and category",
			level: logLevelInfo,
			checks: func(t *testing.T, got string) {
				t.Helper()
				if strings.Count(got, "[x ]") < 2 {
					t.Errorf("expected at least 2 error-icon lines, got %q", got)
				}
				if !strings.Contains(got, "[. ] Detail: dial 1") {
					t.Errorf("output should contain first detail line, got %q", got)
				}
				if !strings.Contains(got, "[. ] Detail: dial 2") {
					t.Errorf("output should contain second detail line, got %q", got)
				}
				if !strings.Contains(got, "[. ] Category: certree: connection failed") {
					t.Errorf("output should contain category line, got %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf strings.Builder
			er := &errReporter{
				w:     &buf,
				icons: render.LogIcons{Error: "[x ]", Continuation: "[. ]"},
				level: tt.level,
			}
			er.writeFormatted(batchErr)
			tt.checks(t, buf.String())
		})
	}
}

func TestErrReporter_WritePartsEmptyMessage(t *testing.T) {
	t.Parallel()

	fe := formattedError{
		message: "",
		detail:  "some detail",
	}
	var buf strings.Builder
	er := &errReporter{
		w:     &buf,
		icons: render.LogIcons{Error: "[x ]", Continuation: "[. ]"},
		level: logLevelInfo,
	}
	er.writeParts(fe)
	got := buf.String()

	// Empty message still produces an error-icon line (documents current behavior).
	want := "[x ] \n[. ] Detail: some detail\n"
	if got != want {
		t.Errorf("writeParts() = %q, want %q", got, want)
	}
}
