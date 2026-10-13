package lsp

import "strings"

// maxDiffEdits bounds the Myers search. Beyond it the changed middle of the
// file is treated as rewritten: findings there stay visible as "code changed
// since the scan" (ADR-042 §4) instead of the server spending unbounded memory
// on a pathological diff. The trace costs O(maxDiffEdits²) ints.
const maxDiffEdits = 1500

// lineMap maps 0-based line numbers of the scanned file onto the current
// buffer.
type lineMap struct {
	// newLine[i] is the current line of scanned line i, or -1 when that line
	// was deleted or rewritten.
	newLine []int
	// insertedAfter[i] is true when lines were inserted between scanned line
	// i and i+1, which edits any finding range spanning both.
	insertedAfter []bool
	newCount      int
}

// identityLineMap is used when the scanned and current contents match or when
// the scanned content is unknown: lines are trusted as-is.
func identityLineMap(n int) *lineMap {
	m := &lineMap{newLine: make([]int, n), insertedAfter: make([]bool, n), newCount: n}
	for i := range m.newLine {
		m.newLine[i] = i
	}
	return m
}

// splitLines splits text into lines without their terminators. A trailing
// newline does not create an extra empty line.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	return strings.Split(text, "\n")
}

// newLineMap diffs old against cur by line.
func newLineMap(old, cur []string) *lineMap {
	m := &lineMap{newLine: make([]int, len(old)), insertedAfter: make([]bool, len(old)), newCount: len(cur)}
	for i := range m.newLine {
		m.newLine[i] = -1
	}

	prefix := 0
	for prefix < len(old) && prefix < len(cur) && old[prefix] == cur[prefix] {
		m.newLine[prefix] = prefix
		prefix++
	}
	suffix := 0
	for suffix < len(old)-prefix && suffix < len(cur)-prefix && old[len(old)-1-suffix] == cur[len(cur)-1-suffix] {
		m.newLine[len(old)-1-suffix] = len(cur) - 1 - suffix
		suffix++
	}

	a, b := old[prefix:len(old)-suffix], cur[prefix:len(cur)-suffix]
	if pairs, ok := myersMatches(a, b); ok {
		for _, p := range pairs {
			m.newLine[prefix+p[0]] = prefix + p[1]
		}
	}

	// Mark insertions: consecutive mapped old lines whose current lines are
	// not adjacent had lines inserted between them.
	prev, prevNew := -1, -1
	for i, j := range m.newLine {
		if j < 0 {
			continue
		}
		if prev >= 0 && j-prevNew > 1 {
			m.insertedAfter[prev] = true
		}
		prev, prevNew = i, j
	}
	return m
}

// myersMatches returns the matching (oldIndex, newIndex) pairs of a shortest
// edit script between a and b, or false when more than maxDiffEdits edits are
// needed.
func myersMatches(a, b []string) ([][2]int, bool) {
	n, mLen := len(a), len(b)
	if n == 0 || mLen == 0 {
		return nil, true
	}
	maxD := n + mLen
	if maxD > maxDiffEdits {
		maxD = maxDiffEdits
	}
	offset := maxD + 1
	v := make([]int, 2*maxD+3)
	var trace [][]int
	found := -1
	for d := 0; d <= maxD && found < 0; d++ {
		snapshot := make([]int, 2*d+1)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1]
			} else {
				x = v[offset+k-1] + 1
			}
			y := x - k
			for x < n && y < mLen && a[x] == b[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x >= n && y >= mLen {
				found = d
			}
		}
		for k := -d; k <= d; k++ {
			snapshot[k+d] = v[offset+k]
		}
		trace = append(trace, snapshot)
	}
	if found < 0 {
		return nil, false
	}

	// Backtrack from (n, mLen) through the saved frontiers.
	var pairs [][2]int
	x, y := n, mLen
	for d := found; d > 0; d-- {
		prevV := trace[d-1]
		at := func(k int) int { return prevV[k+d-1] }
		k := x - y
		var prevK int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := at(prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			pairs = append(pairs, [2]int{x, y})
		}
		x, y = prevX, prevY
	}
	for x > 0 && y > 0 {
		x--
		y--
		pairs = append(pairs, [2]int{x, y})
	}
	return pairs, true
}

// mapRange maps the 0-based inclusive range [start, end] of the scanned file.
// It returns the current range and whether any line of it was edited. A range
// whose lines were all deleted is anchored at the nearest surviving line
// before it, so the finding stays visible.
func (m *lineMap) mapRange(start, end int) (newStart, newEnd int, edited bool) {
	if len(m.newLine) == 0 {
		return start, end, false
	}
	start = clamp(start, 0, len(m.newLine)-1)
	end = clamp(end, start, len(m.newLine)-1)

	newStart, newEnd = -1, -1
	for i := start; i <= end; i++ {
		j := m.newLine[i]
		if j < 0 {
			edited = true
			continue
		}
		if newStart < 0 {
			newStart = j
		}
		newEnd = j
		if i < end && m.insertedAfter[i] {
			edited = true
		}
	}
	if newStart >= 0 {
		return newStart, newEnd, edited
	}
	for i := start - 1; i >= 0; i-- {
		if j := m.newLine[i]; j >= 0 {
			anchor := min(j+1, max(m.newCount-1, 0))
			return anchor, anchor, true
		}
	}
	return 0, 0, true
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
