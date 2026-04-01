// Tree visualization: certificate tree building, merged trie, and rendering.

package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

const (
	// estimatedBytesPerNode is the estimated output bytes per tree node, used
	// for builder preallocation. Based on ~80 chars per node with a 20% buffer
	// for multi-line labels in detailed mode.
	estimatedBytesPerNode = 96

	// pathIndexMarker is a sentinel prefix embedded in labels to mark path
	// index annotations. The format is "\x00PI:1,3\x00" where "1,3" are
	// comma-separated 1-based path indices. Post-processing replaces these
	// with right-aligned "#N" annotations.
	pathIndexMarker = "\x00PI:"

	// pathIndexEnd terminates a path index marker.
	pathIndexEnd = "\x00"
)

// nodeMetadata holds typed metadata for a tree node.
type nodeMetadata struct {
	certificate *certree.Certificate
	path        *certree.TrustPath
	// paths holds all contributing trust paths for merged-view nodes.
	// nil for expanded-view nodes where path holds the single path.
	paths []*certree.TrustPath
	index int
}

// treeNode represents a node in the certificate tree.
type treeNode struct {
	label    string
	children []*treeNode
	// metadata is nil for the synthetic root node.
	metadata *nodeMetadata
}

// certTree represents the complete tree structure.
type certTree struct {
	root *treeNode
}

// treeVisualizer implements tree-based visualization of certificate chains.
type treeVisualizer struct {
	opts  Options
	theme renderTheme
	width int
}

// newTreeVisualizer creates a new tree visualizer from the resolved render environment.
func newTreeVisualizer(env *renderEnv) *treeVisualizer {
	return &treeVisualizer{
		opts:  env.opts,
		theme: env.theme,
		width: env.width,
	}
}

// visualize renders the analysis as a tree. Returns errNoAnalysis if analysis is nil.
func (tv *treeVisualizer) visualize(analysis *certree.Analysis) (string, error) {
	if analysis == nil {
		return "", errNoAnalysis
	}

	var t *certTree
	if tv.opts.ExpandedView {
		t = tv.buildFromAnalysis(analysis)
	} else {
		t = tv.buildMergedFromAnalysis(analysis)
	}
	output := tv.render(t)
	if tv.opts.ShowPathIndex {
		output = alignPathIndices(output, tv.theme.colors.dim)
	}
	return output, nil
}

// visualizeAll renders multiple analyses as trees separated by blank lines.
func (tv *treeVisualizer) visualizeAll(analyses []*certree.Analysis) (string, error) {
	if len(analyses) == 0 {
		return "", errNoAnalysis
	}

	outputs := make([]string, 0, len(analyses))
	totalSize := 0
	for _, analysis := range analyses {
		output, err := tv.visualize(analysis)
		if err != nil {
			return "", err
		}
		outputs = append(outputs, output)
		totalSize += len(output) + 1
	}

	var builder strings.Builder
	builder.Grow(totalSize)
	for i, output := range outputs {
		builder.WriteString(output)
		if i < len(outputs)-1 {
			builder.WriteByte('\n')
		}
	}
	return builder.String(), nil
}

// emptyTree returns a certTree with a single "No trust paths found" root node.
func emptyTree() *certTree {
	return &certTree{
		root: &treeNode{
			label:    "No trust paths found",
			children: []*treeNode{},
		},
	}
}

// buildFromAnalysis creates a tree structure from an Analysis.
func (tv *treeVisualizer) buildFromAnalysis(analysis *certree.Analysis) *certTree {
	if analysis == nil || len(analysis.TrustPaths) == 0 {
		return emptyTree()
	}

	rootLabel := tv.analysisRootLabel(analysis)

	root := &treeNode{
		label:    rootLabel,
		children: make([]*treeNode, 0, len(analysis.TrustPaths)),
	}

	for i, path := range analysis.TrustPaths {
		pathNode := tv.buildPathNode(path, i)
		root.children = append(root.children, pathNode)
	}

	return &certTree{root: root}
}

// buildMergedFromAnalysis creates a merged tree structure from an Analysis.
// Paths sharing the same certificates at the same depth are merged into single nodes.
func (tv *treeVisualizer) buildMergedFromAnalysis(analysis *certree.Analysis) *certTree {
	if analysis == nil || len(analysis.TrustPaths) == 0 {
		return emptyTree()
	}

	rootLabel := tv.analysisRootLabel(analysis)

	merged := buildMergedTree(analysis.TrustPaths, tv.opts.ReverseOrder)
	globalDisambig := globalDisambiguators(analysis)

	var pathIndices map[*certree.TrustPath]int
	if tv.opts.ShowPathIndex {
		pathIndices = buildPathIndexMap(analysis.TrustPaths)
	}

	root := &treeNode{
		label:    rootLabel,
		children: make([]*treeNode, 0, len(merged.order)),
	}

	for _, fp := range merged.order {
		child := tv.convertMergedTreeNode(merged.children[fp], 0, globalDisambig[fp], pathIndices, globalDisambig)
		root.children = append(root.children, child)
	}

	return &certTree{root: root}
}

// analysisRootLabel builds the root label for an analysis tree.
func (tv *treeVisualizer) analysisRootLabel(analysis *certree.Analysis) string {
	icon := tv.statusIcon(analysisStatus(analysis, tv.opts.ExpiryWarningDays))
	suffix := tv.pathCountSuffix(analysis)

	if analysis.Metadata.Source != "" {
		source := tv.theme.colors.source(SanitizeCertString(analysis.Metadata.Source))
		return fmt.Sprintf("%s %s -- %s", icon, source, suffix)
	}
	return icon + " (no source) -- " + suffix
}

// pathCountSuffix returns a differentiated path count string like "3 trusted, 1 untrusted".
// Each trust path is counted individually. A structurally trusted path (reaches
// a trust anchor) is counted as untrusted when it has validation errors
// (expired certs, hostname mismatch, etc.).
func (tv *treeVisualizer) pathCountSuffix(analysis *certree.Analysis) string {
	var trusted, untrusted, incomplete int
	for _, path := range analysis.TrustPaths {
		switch {
		case path.Status == certree.PathIncomplete:
			incomplete++
		case isEffectivelyTrusted(path, tv.opts.ExpiryWarningDays):
			trusted++
		default:
			untrusted++
		}
	}

	total := trusted + untrusted + incomplete
	if total == 0 {
		return "0 paths"
	}

	noun := "paths"
	if total == 1 {
		noun = "path"
	}

	var parts []string
	if trusted > 0 {
		parts = append(parts, fmt.Sprintf("%d trusted", trusted))
	}
	if untrusted > 0 {
		parts = append(parts, fmt.Sprintf("%d untrusted", untrusted))
	}
	if incomplete > 0 {
		parts = append(parts, fmt.Sprintf("%d incomplete", incomplete))
	}
	return strings.Join(parts, ", ") + " " + noun
}

// convertMergedTreeNode recursively converts a mergedTreeNode into a treeNode for rendering.
// pathIndices maps trust paths to their 1-based display indices; nil when path indexing is disabled.
// globalDisambig maps fingerprints to short prefixes for all certs that share a display name
// anywhere in the analysis, ensuring consistent disambiguation regardless of tree position.
func (tv *treeVisualizer) convertMergedTreeNode(mn *mergedTreeNode, depth int, disambig string, pathIndices map[*certree.TrustPath]int, globalDisambig map[string]string) *treeNode {
	worstPath := tv.worstCertPath(mn.cert, mn.paths)
	label := tv.formatMergedCertLabel(mn.cert, mn.paths, worstPath, depth, disambig)

	if pathIndices != nil {
		if marker := terminalPathMarker(mn, pathIndices); marker != "" {
			// Append marker to the first line only (multi-line labels have
			// detail fields on subsequent lines).
			if nl := strings.IndexByte(label, '\n'); nl >= 0 {
				label = label[:nl] + marker + label[nl:]
			} else {
				label += marker
			}
		}
	}

	node := &treeNode{
		label: label,
		metadata: &nodeMetadata{
			certificate: mn.cert,
			path:        worstPath,
			paths:       mn.paths,
		},
		children: make([]*treeNode, 0, len(mn.order)),
	}

	for _, fp := range mn.order {
		child := tv.convertMergedTreeNode(mn.children[fp], depth+1, globalDisambig[fp], pathIndices, globalDisambig)
		node.children = append(node.children, child)
	}

	return node
}

// formatMergedCertLabel creates a single- or multi-line label for a merged cert node.
func (tv *treeVisualizer) formatMergedCertLabel(cert *certree.Certificate, paths []*certree.TrustPath, worstPath *certree.TrustPath, depth int, disambig string) string {
	s := mergedCertStatus(cert, paths, tv.opts.ExpiryWarningDays)
	icon := tv.statusIcon(s.level)
	cn := displayName(cert)
	var annotation string
	if tv.opts.ShowAnnotations {
		annotation = tv.colorizeReasons(s.reasons, s.level)
	}
	var formattedDisambig string
	if disambig != "" {
		formattedDisambig = tv.theme.colors.dim(disambig)
	}
	return tv.buildCertLabel(cert, worstPath, paths, icon, cn, formattedDisambig, annotation, depth)
}

// buildPathNode creates a node for a trust path.
func (tv *treeVisualizer) buildPathNode(path *certree.TrustPath, index int) *treeNode {
	if path == nil || len(path.Certificates) == 0 {
		return &treeNode{
			label:    fmt.Sprintf("Trust Path %d: Empty", index+1),
			children: []*treeNode{},
		}
	}

	level := pathStatus(path, tv.opts.ExpiryWarningDays)
	icon := tv.statusIcon(level)
	pathLabel := fmt.Sprintf("%s Trust Path %d", icon, index+1)

	if tv.opts.ShowAnnotations {
		if reason := pathStatusReason(path, tv.opts.ExpiryWarningDays); reason != "" {
			colorFn := tv.statusColorFunc(level)
			pathLabel += " (" + colorFn(reason) + ")"
		}
	}

	pathNode := &treeNode{
		label:    pathLabel,
		children: make([]*treeNode, 0, 1),
		metadata: &nodeMetadata{path: path, index: index},
	}

	// When ReverseOrder is true, iterate root-to-leaf but pass the original
	// index to buildCertNode so metadata stays correct.
	var currentNode *treeNode
	n := len(path.Certificates)

	for i := range n {
		var certIdx int
		if tv.opts.ReverseOrder {
			certIdx = n - 1 - i
		} else {
			certIdx = i
		}
		cert := path.Certificates[certIdx]
		// Pass display depth (i) for wrap-width calculation, certIdx for metadata.
		certNode := tv.buildCertNode(cert, path, certIdx, i)

		// Append path index marker to the root certificate (last in the
		// leaf-to-root slice), matching the merged view convention.
		if tv.opts.ShowPathIndex && certIdx == n-1 {
			marker := fmt.Sprintf("%s#%d%s", pathIndexMarker, index+1, pathIndexEnd)
			if nl := strings.IndexByte(certNode.label, '\n'); nl >= 0 {
				certNode.label = certNode.label[:nl] + marker + certNode.label[nl:]
			} else {
				certNode.label += marker
			}
		}

		if i == 0 {
			pathNode.children = append(pathNode.children, certNode)
		} else {
			currentNode.children = append(currentNode.children, certNode)
		}
		currentNode = certNode
	}

	return pathNode
}

// buildCertNode creates a node for an individual certificate.
// displayDepth is the node's position in the rendered tree (for wrap-width);
// index is the cert's position in path.Certificates (for metadata).
func (tv *treeVisualizer) buildCertNode(cert *certree.Certificate, path *certree.TrustPath, index, displayDepth int) *treeNode {
	label := tv.formatCertLabel(cert, path, displayDepth)
	return &treeNode{
		label:    label,
		metadata: &nodeMetadata{certificate: cert, path: path, index: index},
	}
}

// statusIcon returns the theme's pre-colorized icon for the given status level.
func (tv *treeVisualizer) statusIcon(level statusLevel) string {
	switch level {
	case statusError:
		return tv.theme.statusIcons.err
	case statusWarning:
		return tv.theme.statusIcons.warning
	default:
		return tv.theme.statusIcons.valid
	}
}

// worstCertPath returns the path where cert has the highest severity status.
func (tv *treeVisualizer) worstCertPath(cert *certree.Certificate, paths []*certree.TrustPath) *certree.TrustPath {
	if len(paths) == 0 {
		return nil
	}
	worst := paths[0]
	worstLevel := certStatus(cert, worst, tv.opts.ExpiryWarningDays).level
	for _, p := range paths[1:] {
		level := certStatus(cert, p, tv.opts.ExpiryWarningDays).level
		if level == statusError {
			return p
		}
		if level > worstLevel {
			worst = p
			worstLevel = level
		}
	}
	return worst
}

// statusColorFunc returns the color function for the given status level.
func (tv *treeVisualizer) statusColorFunc(level statusLevel) colorFunc {
	switch level {
	case statusError:
		return tv.theme.colors.err
	case statusWarning:
		return tv.theme.colors.warning
	default:
		return tv.theme.colors.valid
	}
}

// mergedTreeNode is an intermediate node in the merged certificate tree.
// Paths sharing the same certificate (by fingerprint) at the same depth
// are collapsed into a single node, then converted to treeNode for rendering.
type mergedTreeNode struct {
	cert     *certree.Certificate
	paths    []*certree.TrustPath
	children map[string]*mergedTreeNode
	// order preserves insertion order for deterministic sibling rendering.
	order []string
}

// buildMergedTree constructs a merged certificate tree from trust paths.
// Walks each path's certificate sequence leaf-to-root (or root-to-leaf when
// reverse is true), collapsing nodes that share the same fingerprint at the
// same depth. The returned root is synthetic (no cert, no paths).
func buildMergedTree(paths []*certree.TrustPath, reverse bool) *mergedTreeNode {
	root := &mergedTreeNode{children: make(map[string]*mergedTreeNode)}

	for _, path := range paths {
		if path == nil || len(path.Certificates) == 0 {
			continue
		}

		node := root
		n := len(path.Certificates)
		for i := range n {
			var certIdx int
			if reverse {
				certIdx = n - 1 - i
			} else {
				certIdx = i
			}
			cert := path.Certificates[certIdx]
			if cert == nil {
				continue
			}

			fp := cert.FingerprintSHA256()
			child, exists := node.children[fp]
			if !exists {
				child = &mergedTreeNode{
					cert:     cert,
					children: make(map[string]*mergedTreeNode),
				}
				node.children[fp] = child
				node.order = append(node.order, fp)
			}
			child.paths = append(child.paths, path)
			node = child
		}
	}

	return root
}

// globalDisambiguators returns a map of fingerprint to short prefix for all
// certificates in the analysis that share a display name with at least one
// other certificate. Unlike sibling-only disambiguation, this ensures
// consistent fingerprint suffixes regardless of tree structure (e.g., certs
// that are siblings in leaf-to-root order but cousins in root-to-leaf order).
func globalDisambiguators(analysis *certree.Analysis) map[string]string {
	seen := make(map[string]struct{})
	var certs []*certree.Certificate
	for _, tp := range analysis.TrustPaths {
		for _, c := range tp.Certificates {
			fp := c.FingerprintSHA256()
			if _, ok := seen[fp]; !ok {
				seen[fp] = struct{}{}
				certs = append(certs, c)
			}
		}
	}
	return disambiguateNames(certs)
}

// buildPathIndexMap creates a mapping from each TrustPath pointer to its
// 1-based display index, preserving the analysis ordering.
func buildPathIndexMap(paths []*certree.TrustPath) map[*certree.TrustPath]int {
	m := make(map[*certree.TrustPath]int, len(paths))
	for i, p := range paths {
		m[p] = i + 1
	}
	return m
}

// terminalPathMarker returns a path index marker string for a merged node
// if any of its contributing paths have their outermost divergence point at
// this node. In default (leaf-to-root) order, this is the last certificate
// (deepest root). In reverse (root-to-leaf) order, this is the first
// certificate (topmost root), placing the index where the eye starts reading.
func terminalPathMarker(mn *mergedTreeNode, pathIndices map[*certree.TrustPath]int) string {
	if mn.cert == nil || len(mn.paths) == 0 {
		return ""
	}
	fp := mn.cert.FingerprintSHA256()
	var indices []int
	for _, p := range mn.paths {
		if len(p.Certificates) == 0 {
			continue
		}
		// Mark the root certificate (last in the leaf-to-root slice).
		// In default display it's at the bottom (deepest divergence point);
		// in reversed display it's at the top (where the eye starts reading).
		// Both place the index where paths are unique.
		markerCert := p.Certificates[len(p.Certificates)-1]
		if markerCert != nil && markerCert.FingerprintSHA256() == fp {
			if idx, ok := pathIndices[p]; ok {
				indices = append(indices, idx)
			}
		}
	}
	if len(indices) == 0 {
		return ""
	}
	slices.Sort(indices)
	parts := make([]string, len(indices))
	for i, idx := range indices {
		parts[i] = fmt.Sprintf("#%d", idx)
	}
	return pathIndexMarker + strings.Join(parts, ", ") + pathIndexEnd
}

// alignPathIndices post-processes rendered tree output to replace embedded
// path index markers with right-aligned annotations. All markers are aligned
// to the same column with at least two spaces of gap.
func alignPathIndices(output string, colorFn colorFunc) string {
	lines := strings.Split(output, "\n")

	// First pass: find max visible content width and collect marker info.
	type markerInfo struct {
		lineIdx    int
		contentEnd int    // byte position where marker starts
		text       string // e.g. "#1" or "#1, #3"
	}
	var markers []markerInfo
	maxContentWidth := 0

	for i, line := range lines {
		markerStart := strings.Index(line, pathIndexMarker)
		if markerStart < 0 {
			continue
		}
		markerEnd := strings.Index(line[markerStart+len(pathIndexMarker):], pathIndexEnd)
		if markerEnd < 0 {
			continue
		}
		markerEnd += markerStart + len(pathIndexMarker)
		text := line[markerStart+len(pathIndexMarker) : markerEnd]
		content := line[:markerStart]
		contentWidth := visibleLen(content)
		if contentWidth > maxContentWidth {
			maxContentWidth = contentWidth
		}
		markers = append(markers, markerInfo{
			lineIdx:    i,
			contentEnd: markerStart,
			text:       text,
		})
	}

	if len(markers) == 0 {
		return output
	}

	// Second pass: replace markers with right-aligned text.
	alignCol := maxContentWidth + 2
	for _, m := range markers {
		content := lines[m.lineIdx][:m.contentEnd]
		afterMarker := lines[m.lineIdx][m.contentEnd+len(pathIndexMarker)+len(m.text)+len(pathIndexEnd):]
		contentWidth := visibleLen(content)
		padding := max(alignCol-contentWidth, 2)
		lines[m.lineIdx] = content + strings.Repeat(" ", padding) + colorFn(m.text) + afterMarker
	}

	return strings.Join(lines, "\n")
}

// colorizeReasons returns a parenthesized, colored annotation string for the
// given status reasons, or empty string if reasons is empty.
func (tv *treeVisualizer) colorizeReasons(reasons []string, level statusLevel) string {
	if len(reasons) == 0 {
		return ""
	}
	defaultColorFn := tv.statusColorFunc(level)
	// When "trusted" is present, the other reasons are informational
	// issues on an otherwise-valid cert -- color them as warnings.
	if slices.Contains(reasons, "trusted") {
		defaultColorFn = tv.theme.colors.warning
	}
	colored := make([]string, len(reasons))
	for i, r := range reasons {
		switch r {
		case "trusted":
			colored[i] = tv.theme.colors.valid(r)
		case "injected":
			colored[i] = tv.theme.colors.injected(r)
		default:
			colored[i] = defaultColorFn(r)
		}
	}
	return "(" + strings.Join(colored, ", ") + ")"
}

// buildCertLabel assembles the final label string from status icon, display
// name, disambiguator, annotation, and optional detail lines.
// Both disambig and annotation arrive pre-formatted (colorized) or empty.
func (tv *treeVisualizer) buildCertLabel(cert *certree.Certificate, path *certree.TrustPath, paths []*certree.TrustPath, status, cn, disambig, annotation string, depth int) string {
	if !tv.opts.hasDetailFlags() {
		var b strings.Builder
		b.WriteString(status)
		b.WriteByte(' ')
		b.WriteString(cn)
		if disambig != "" {
			b.WriteByte(' ')
			b.WriteString(disambig)
		}
		if annotation != "" {
			b.WriteByte(' ')
			b.WriteString(annotation)
		}
		return b.String()
	}

	parts := make([]string, 0, 4)
	parts = append(parts, status, cn)
	if disambig != "" {
		parts = append(parts, disambig)
	}
	if annotation != "" {
		parts = append(parts, annotation)
	}
	return tv.formatDetailedLabel(cert, path, paths, parts, depth)
}

// formatCertLabel creates a single- or multi-line label for a certificate node.
func (tv *treeVisualizer) formatCertLabel(cert *certree.Certificate, path *certree.TrustPath, depth int) string {
	s := certStatus(cert, path, tv.opts.ExpiryWarningDays)
	icon := tv.statusIcon(s.level)
	cn := displayName(cert)
	var annotation string
	if tv.opts.ShowAnnotations {
		annotation = tv.colorizeReasons(s.reasons, s.level)
	}
	return tv.buildCertLabel(cert, path, nil, icon, cn, "", annotation, depth)
}

// formatDetailedLabel creates a multi-line label for detailed mode.
// paths is non-nil for merged-view nodes (aggregated warnings/errors).
func (tv *treeVisualizer) formatDetailedLabel(cert *certree.Certificate, path *certree.TrustPath, paths []*certree.TrustPath, baseParts []string, depth int) string {
	lines := []string{strings.Join(baseParts, " ")}

	statusIconWidth := 0
	if len(baseParts) > 0 {
		statusIconWidth = visibleLen(baseParts[0])
	}
	lines = tv.appendBasicDetailLines(cert, path, paths, lines, depth, statusIconWidth)

	// Indent detail lines by the status icon width so values align under the CN.
	if statusIconWidth > 0 && len(lines) > 1 {
		pad := strings.Repeat(" ", statusIconWidth)
		for i := 1; i < len(lines); i++ {
			lines[i] = pad + lines[i]
		}
	}

	return strings.Join(lines, "\n")
}

// appendBasicDetailLines appends detail lines for all enabled --show-* flags.
// paths is non-nil for merged-view nodes (aggregated warnings/errors).
//
//nolint:gocyclo,cyclop // linear feature-flag assembly, each block is an independent guard
func (tv *treeVisualizer) appendBasicDetailLines(cert *certree.Certificate, path *certree.TrustPath, paths []*certree.TrustPath, lines []string, depth, statusIconWidth int) []string {
	var sections []certSection
	indent := tv.theme.treeChars.sectionIndent
	sep := tv.theme.treeChars.labelSep

	if tv.opts.ShowSubject {
		block := sectionBlock{header: "Subject:", labelSep: sep}
		block.lines = formatDNFields(cert.Raw().Subject, indent, sep)
		sections = append(sections, block)
	}

	if tv.opts.ShowSAN {
		if block, ok := buildSANSection(cert, indent, sep); ok {
			sections = append(sections, block)
		}
	}

	if tv.opts.ShowIssuer {
		header := "Issuer:"
		if cert.IsSelfSigned() {
			colorFn := tv.theme.colors.err
			if len(cert.Metadata().TrustedLocations) > 0 {
				colorFn = tv.theme.colors.valid
			}
			header = "Issuer: (" + colorFn("self-signed") + ")"
		}
		block := sectionBlock{header: header, labelSep: sep}
		block.lines = formatDNFields(cert.Raw().Issuer, indent, sep)
		sections = append(sections, block)
	}

	if tv.opts.ShowValidity {
		sections = append(sections, buildValiditySection(cert, indent, sep, tv.theme.colors.err, tv.theme.colors.warning, tv.theme.colors.dim, tv.opts.ExpiryWarningDays))
	}

	if tv.opts.ShowTrustStore {
		if v := trustStoreValue(cert); v != "" {
			sections = append(sections, detailField{"Trust Store", v, sep})
		}
	}

	if tv.opts.ShowSerial && cert.Raw().SerialNumber != nil {
		sections = append(sections, detailField{"Serial", certree.ColonHex(cert.SerialNumber()), sep})
	}

	if tv.opts.ShowFingerprint {
		sections = append(sections, detailField{"Fingerprint", certree.ColonHex(cert.FingerprintSHA256()), sep})
	}

	if tv.opts.ShowAlgorithm {
		sections = append(sections,
			detailField{"Signature Algorithm", cert.Raw().SignatureAlgorithm.String(), sep},
			detailField{"Public Key", publicKeyInfo(cert), sep},
		)
	}

	if tv.opts.ShowExtensions {
		if block, ok := buildExtensionsSection(cert, indent, sep); ok {
			sections = append(sections, block)
		}
	}

	if tv.opts.ShowAIA {
		if block, ok := buildAIASection(cert, indent, sep); ok {
			sections = append(sections, block)
		}
	}

	if tv.opts.ShowCRL {
		if block, ok := buildCRLSection(cert, indent, sep); ok {
			sections = append(sections, block)
		}
	}

	if tv.opts.ShowSource {
		src := cert.Source()
		loc := src.Location
		if loc == "" {
			loc = src.Type.String()
		}
		sections = append(sections, detailField{"Source", SanitizeCertString(loc), sep})
	}

	// Always appended: ShowDiagnostics enables multi-line mode via
	// hasDetailFlags() without setting other Show* flags, so only
	// warnings/errors sections appear.
	sections = tv.appendWarningErrorSections(cert, path, paths, sections)

	maxLabel := 0
	for _, s := range sections {
		if w := s.labelWidth(); w > maxLabel {
			maxLabel = w
		}
	}

	availWidth := tv.valueColumnWidth(depth, statusIconWidth, maxLabel)

	for _, s := range sections {
		lines = append(lines, s.renderLines(maxLabel, availWidth)...)
	}

	return lines
}

// appendWarningErrorSections appends Warnings and Errors sectionBlocks for the given certificate.
// When paths is non-nil (merged node), warnings and errors are aggregated across all paths.
func (tv *treeVisualizer) appendWarningErrorSections(cert *certree.Certificate, path *certree.TrustPath, paths []*certree.TrustPath, sections []certSection) []certSection {
	indent := tv.theme.treeChars.sectionIndent
	sep := tv.theme.treeChars.labelSep
	fp := cert.FingerprintSHA256()

	var scanPaths []*certree.TrustPath
	switch {
	case paths != nil:
		scanPaths = paths
	case path != nil:
		scanPaths = []*certree.TrustPath{path}
	default:
		return sections
	}

	seenWarnings := make(map[string]struct{})
	var warningLines []string
	for _, p := range scanPaths {
		for _, w := range p.Warnings {
			if w.Certificate == nil || w.Certificate.FingerprintSHA256() != fp {
				continue
			}
			if w.Type == certree.WarningExcludedBySimulation {
				continue
			}
			if _, ok := seenWarnings[w.Message]; ok {
				continue
			}
			seenWarnings[w.Message] = struct{}{}
			warningLines = append(warningLines, indent+"- "+tv.theme.colors.warning(SanitizeCertString(w.Message)))
		}
	}
	if len(warningLines) > 0 {
		sections = append(sections, sectionBlock{header: "Warnings:", lines: warningLines, labelSep: sep})
	}

	seenErrors := make(map[string]struct{})
	var errorLines []string
	for _, p := range scanPaths {
		for _, e := range p.Errors {
			if e.Certificate == nil || e.Certificate.FingerprintSHA256() != fp {
				continue
			}
			if _, ok := seenErrors[e.Message]; ok {
				continue
			}
			seenErrors[e.Message] = struct{}{}
			errorLines = append(errorLines, indent+"- "+tv.theme.colors.err(SanitizeCertString(e.Message)))
		}
	}
	if len(errorLines) > 0 {
		sections = append(sections, sectionBlock{header: "Errors:", lines: errorLines, labelSep: sep})
	}

	return sections
}

// render renders the certificate tree and returns the output as a string.
func (tv *treeVisualizer) render(t *certTree) string {
	if t == nil || t.root == nil {
		return ""
	}

	var builder strings.Builder
	builder.Grow(estimateOutputSize(t))

	tv.renderNode(&builder, t.root, "", true, true)

	return builder.String()
}

// estimateOutputSize estimates the size of the output string for the given tree.
func estimateOutputSize(t *certTree) int {
	if t == nil || t.root == nil {
		return 0
	}
	return t.root.countNodes() * estimatedBytesPerNode
}

// countNodes counts the total number of nodes in the subtree rooted at this node.
func (n *treeNode) countNodes() int {
	count := 1
	for _, child := range n.children {
		count += child.countNodes()
	}
	return count
}

// isGhosted reports whether this node represents a ghosted certificate.
// For merged nodes, the cert is ghosted only if it is ghosted in ALL paths.
func (n *treeNode) isGhosted() bool {
	if n.metadata == nil || n.metadata.certificate == nil {
		return false
	}

	if n.metadata.paths != nil {
		for _, p := range n.metadata.paths {
			if !p.IsGhosted(n.metadata.certificate) {
				return false
			}
		}
		return len(n.metadata.paths) > 0
	}

	if n.metadata.path == nil {
		return false
	}
	return n.metadata.path.IsGhosted(n.metadata.certificate)
}

// renderNode recursively renders a node and its children.
func (tv *treeVisualizer) renderNode(builder *strings.Builder, node *treeNode, prefix string, isLast bool, isRoot bool) {
	if node == nil {
		return
	}

	ghosted := node.isGhosted()

	var nodePrefix string
	switch {
	case isRoot:
		nodePrefix = ""
	case isLast:
		nodePrefix = tv.theme.treeChars.lastChild
	default:
		nodePrefix = tv.theme.treeChars.branch
	}

	writeLine := func(line string) {
		if ghosted {
			builder.WriteString(tv.theme.colors.dim(stripANSICodes(line)))
		} else {
			builder.WriteString(line)
		}
		builder.WriteByte('\n')
	}

	buildHeaderLine := func(content string) string {
		var lb strings.Builder
		lb.WriteString(prefix)
		lb.WriteString(nodePrefix)
		lb.WriteString(content)
		return lb.String()
	}

	buildDetailLine := func(content string, hasChildren bool) string {
		detailContinue := tv.theme.treeChars.vertical
		detailEnd := tv.theme.treeChars.blank

		var lb strings.Builder
		lb.WriteString(prefix)
		if !isRoot {
			if nodePrefix != "" {
				// Sibling continuation in the nodePrefix area (where "+- " was).
				if !isLast {
					lb.WriteString(detailContinue)
				} else {
					lb.WriteString(detailEnd)
				}
				// Child continuation below this node.
				if hasChildren {
					lb.WriteString(detailContinue)
				} else {
					lb.WriteString(detailEnd)
				}
			} else {
				// Minimal theme: no branch connector, single continuation.
				if hasChildren || !isLast {
					lb.WriteString(detailContinue)
				} else {
					lb.WriteString(detailEnd)
				}
			}
		}
		lb.WriteString(content)
		return lb.String()
	}

	if !strings.Contains(node.label, "\n") {
		writeLine(buildHeaderLine(node.label))
	} else {
		lines := strings.Split(node.label, "\n")
		hasChildren := len(node.children) > 0
		for i, line := range lines {
			if i == 0 {
				writeLine(buildHeaderLine(line))
			} else {
				writeLine(buildDetailLine(line, hasChildren))
			}
		}
	}

	var childPrefix string
	switch {
	case isRoot:
		// Themes with visible connectors (branch != "") let the connector provide
		// indentation, so the tree spine aligns with the root's opening bracket.
		// Themes without connectors (minimal) rely on empty-space indentation.
		if tv.theme.treeChars.branch != "" {
			childPrefix = ""
		} else {
			childPrefix = tv.theme.treeChars.blank
		}
	case isLast:
		childPrefix = prefix + tv.theme.treeChars.blank
	default:
		childPrefix = prefix + tv.theme.treeChars.vertical
	}

	for i, child := range node.children {
		isLastChild := i == len(node.children)-1
		tv.renderNode(builder, child, childPrefix, isLastChild, false)
	}
}

// valueColumnWidth computes the available width for detail values at the given tree depth.
func (tv *treeVisualizer) valueColumnWidth(depth, statusIconWidth, maxLabel int) int {
	if !tv.opts.WrapLines || tv.width == 0 {
		return 0
	}
	treeDepth := depth + 2
	// Uses branch width; all built-in themes have equal branch/lastChild
	// widths, so this is correct for last-child lines as well.
	prefixWidth := treeDepth*visibleLen(tv.theme.treeChars.vertical) +
		visibleLen(tv.theme.treeChars.branch) + 1
	labelColWidth := maxLabel + 1 + visibleLen(tv.theme.treeChars.labelSep)
	overhead := prefixWidth + statusIconWidth + labelColWidth
	avail := tv.width - overhead
	if avail < minValueWidth {
		return 0
	}
	return avail
}
