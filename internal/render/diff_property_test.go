package render

import (
	"reflect"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// diffTestParams returns gopter parameters with reduced iterations in short mode.
func diffTestParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	if testing.Short() {
		p.MinSuccessfulTests = 10
	} else {
		p.MinSuccessfulTests = 100
	}
	return p
}

// genMultiLineString generates random multi-line strings by joining random
// alpha strings with newlines. Line count ranges from 0 to 10.
func genMultiLineString() gopter.Gen {
	return gen.IntRange(0, 10).FlatMap(func(v any) gopter.Gen {
		n := v.(int)
		if n == 0 {
			return gen.Const("")
		}
		return gen.SliceOfN(n, gen.AlphaString()).Map(func(lines []string) string {
			return strings.Join(lines, "\n")
		})
	}, reflect.TypeFor[string]())
}

func TestProperty_DiffReconstruction(t *testing.T) {
	t.Parallel()

	params := diffTestParams()
	properties := gopter.NewProperties(params)

	properties.Property("applying diff reconstructs the after string", prop.ForAll(
		func(before, after string) bool {
			diffLines := computeLineDiff(before, after)

			// Apply the diff: drop "-" lines, keep "+" and " " lines with prefix stripped.
			var reconstructed []string
			for _, line := range diffLines {
				if len(line) == 0 {
					return false
				}
				switch line[0] {
				case '-':
					// Removed line: skip.
				case '+', ' ':
					reconstructed = append(reconstructed, line[1:])
				default:
					return false
				}
			}

			result := strings.Join(reconstructed, "\n")
			expected := strings.TrimRight(after, "\n")

			return result == expected
		},
		genMultiLineString(),
		genMultiLineString(),
	))

	properties.TestingRun(t)
}
