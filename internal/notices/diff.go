package notices

import (
	"fmt"
	"strings"
)

// maxDiffCells bounds the comparison table of Diff.
const maxDiffCells = 4_000_000

// Diff returns a line diff from the committed text to the generated one
// ("-" only in committed, "+" only in generated), limited to maxLines lines
// of output. Empty when both are equal.
func Diff(committed, generated string, maxLines int) string {
	if committed == generated {
		return ""
	}
	a := strings.Split(committed, "\n")
	b := strings.Split(generated, "\n")
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	a, b = a[prefix:len(a)-suffix], b[prefix:len(b)-suffix]

	var out []string
	if len(a)*len(b) > maxDiffCells {
		out = append(out, fmt.Sprintf("@@ line %d: %d committed lines replaced by %d generated lines (too large to align) @@", prefix+1, len(a), len(b)))
	} else {
		// Longest common subsequence, then walk it.
		lcs := make([][]int32, len(a)+1)
		for i := range lcs {
			lcs[i] = make([]int32, len(b)+1)
		}
		for i := len(a) - 1; i >= 0; i-- {
			for j := len(b) - 1; j >= 0; j-- {
				switch {
				case a[i] == b[j]:
					lcs[i][j] = lcs[i+1][j+1] + 1
				case lcs[i+1][j] >= lcs[i][j+1]:
					lcs[i][j] = lcs[i+1][j]
				default:
					lcs[i][j] = lcs[i][j+1]
				}
			}
		}
		out = append(out, fmt.Sprintf("@@ from line %d @@", prefix+1))
		i, j := 0, 0
		for i < len(a) || j < len(b) {
			switch {
			case i < len(a) && j < len(b) && a[i] == b[j]:
				i++
				j++
			case j < len(b) && (i == len(a) || lcs[i][j+1] > lcs[i+1][j]):
				out = append(out, "+"+b[j])
				j++
			default:
				out = append(out, "-"+a[i])
				i++
			}
		}
	}
	if maxLines > 0 && len(out) > maxLines {
		hidden := len(out) - maxLines
		out = append(out[:maxLines], fmt.Sprintf("... %d more changed lines", hidden))
	}
	return strings.Join(out, "\n") + "\n"
}
