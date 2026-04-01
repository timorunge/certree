// Package render provides certificate analysis visualization for terminal output.
//
// The package renders certree analysis results as tree views for human
// consumption. It supports a default flat view (one line per certificate)
// and detailed mode (activated by the --fields flag or the fields config
// option), three themes (classic, terse, minimal), and optional ANSI color
// output that respects NO_COLOR and TTY detection.
//
// Primary entry points:
//   - [Trees]: Produces tree output for one or more analyses
//   - [Comparisons]: Produces side-by-side before/after comparison
//   - [Diffs]: Produces unified diffs of before/after simulation
//   - [ImpactSummary]: Computes impact summary between two analyses
//
// Terminal and theme utilities:
//   - [ThemeNames]: Returns available theme names
//   - [LookupLogIcons]: Returns log-level icons for a theme
//   - [SpinnerFrames]: Returns spinner animation frames for a theme
//   - [TerminalWidth]: Detects terminal width
//   - [StderrColorEnabled]: Reports whether stderr supports color
package render
