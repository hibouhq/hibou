package comparison

import "sort"

// TestReportInput is one snapshot's test report plus its cases.
type TestReportInput struct {
	HasData         bool
	Format          string
	Total           int
	Passed          int
	Failed          int
	Skipped         int
	Errors          int
	DurationSeconds float64
	Cases           []TestCaseInput
}

// TestCaseInput is a single test case within a report.
type TestCaseInput struct {
	Suite           string
	Name            string
	Classname       string
	Status          string
	DurationSeconds float64
	Message         string
	FilePath        string
}

// TestTotals is the report-level summary used on each side of a diff.
type TestTotals struct {
	Format          string  `json:"format"`
	Total           int     `json:"total"`
	Passed          int     `json:"passed"`
	Failed          int     `json:"failed"`
	Skipped         int     `json:"skipped"`
	Errors          int     `json:"errors"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// TestCaseDelta is a single test case's change between base and head.
type TestCaseDelta struct {
	Suite         string  `json:"suite"`
	Name          string  `json:"name"`
	Classname     string  `json:"classname"`
	FilePath      string  `json:"file_path"`
	Change        string  `json:"change"` // added|removed|status_changed|slower|faster
	BaseStatus    string  `json:"base_status"`
	HeadStatus    string  `json:"head_status"`
	BaseDuration  float64 `json:"base_duration_seconds"`
	HeadDuration  float64 `json:"head_duration_seconds"`
	DurationDelta float64 `json:"duration_delta_seconds"`
	Message       string  `json:"message"`
}

// TestDiff is the full test comparison between two snapshots.
type TestDiff struct {
	Base                 *TestTotals     `json:"base"`
	Head                 *TestTotals     `json:"head"`
	DurationDeltaSeconds float64         `json:"duration_delta_seconds"`
	Added                []TestCaseDelta `json:"added"`
	Removed              []TestCaseDelta `json:"removed"`
	StatusChanged        []TestCaseDelta `json:"status_changed"`
	Slower               []TestCaseDelta `json:"slower"`
	Faster               []TestCaseDelta `json:"faster"`
	Unchanged            int             `json:"unchanged"`
}

// Timing-significance heuristic constants. A duration change must clear the
// absolute floor and then either a proportional threshold or the small-base
// "newly expensive" path. See ADR-016.
const (
	timingAbsFloorSeconds  = 0.05
	timingRelThreshold     = 0.50
	timingSmallBaseSeconds = 0.01
	timingNewCostSeconds   = 0.20
)

// BuildTestDiff compares two snapshots' test reports. It returns nil only when
// neither side has test data.
func BuildTestDiff(base, head TestReportInput) *TestDiff {
	if !base.HasData && !head.HasData {
		return nil
	}

	diff := &TestDiff{
		Added:         []TestCaseDelta{},
		Removed:       []TestCaseDelta{},
		StatusChanged: []TestCaseDelta{},
		Slower:        []TestCaseDelta{},
		Faster:        []TestCaseDelta{},
	}
	if base.HasData {
		diff.Base = testTotalsFromInput(base)
	}
	if head.HasData {
		diff.Head = testTotalsFromInput(head)
	}
	diff.DurationDeltaSeconds = head.DurationSeconds - base.DurationSeconds

	baseCases := indexTestCases(base.Cases)
	headCases := indexTestCases(head.Cases)

	for key, headCase := range headCases {
		baseCase, ok := baseCases[key]
		if !ok {
			diff.Added = append(diff.Added, testCaseDelta("added", TestCaseInput{}, headCase))
			continue
		}
		classifyChangedCase(diff, baseCase, headCase)
	}
	for key, baseCase := range baseCases {
		if _, ok := headCases[key]; ok {
			continue
		}
		diff.Removed = append(diff.Removed, testCaseDelta("removed", baseCase, TestCaseInput{}))
	}

	sortByName(diff.Added)
	sortByName(diff.Removed)
	sortByName(diff.StatusChanged)
	sortBySlowdown(diff.Slower)
	sortBySlowdown(diff.Faster)
	return diff
}

func classifyChangedCase(diff *TestDiff, base, head TestCaseInput) {
	if base.Status != head.Status {
		diff.StatusChanged = append(diff.StatusChanged, testCaseDelta("status_changed", base, head))
		return
	}
	switch significantTiming(base.DurationSeconds, head.DurationSeconds) {
	case timingSlower:
		diff.Slower = append(diff.Slower, testCaseDelta("slower", base, head))
	case timingFaster:
		diff.Faster = append(diff.Faster, testCaseDelta("faster", base, head))
	default:
		diff.Unchanged++
	}
}

type timingDirection int

const (
	timingNone timingDirection = iota
	timingSlower
	timingFaster
)

// significantTiming reports whether a duration change is meaningful and in which
// direction, using the proportional heuristic described in ADR-016.
func significantTiming(base, head float64) timingDirection {
	delta := head - base
	abs := delta
	if abs < 0 {
		abs = -abs
	}
	if abs < timingAbsFloorSeconds {
		return timingNone
	}
	significant := (base > 0 && abs/base >= timingRelThreshold) ||
		(base <= timingSmallBaseSeconds && head >= timingNewCostSeconds)
	if !significant {
		return timingNone
	}
	if delta > 0 {
		return timingSlower
	}
	return timingFaster
}

func testTotalsFromInput(in TestReportInput) *TestTotals {
	return &TestTotals{
		Format:          in.Format,
		Total:           in.Total,
		Passed:          in.Passed,
		Failed:          in.Failed,
		Skipped:         in.Skipped,
		Errors:          in.Errors,
		DurationSeconds: in.DurationSeconds,
	}
}

func indexTestCases(cases []TestCaseInput) map[string]TestCaseInput {
	index := make(map[string]TestCaseInput, len(cases))
	for _, c := range cases {
		index[testCaseKey(c)] = c
	}
	return index
}

func testCaseKey(c TestCaseInput) string {
	return c.Suite + "\x00" + c.Classname + "\x00" + c.Name
}

func testCaseDelta(change string, base, head TestCaseInput) TestCaseDelta {
	identity := head
	if change == "removed" {
		identity = base
	}
	delta := TestCaseDelta{
		Suite:         identity.Suite,
		Name:          identity.Name,
		Classname:     identity.Classname,
		FilePath:      identity.FilePath,
		Change:        change,
		BaseStatus:    base.Status,
		HeadStatus:    head.Status,
		BaseDuration:  base.DurationSeconds,
		HeadDuration:  head.DurationSeconds,
		DurationDelta: head.DurationSeconds - base.DurationSeconds,
		Message:       head.Message,
	}
	if change == "removed" {
		delta.Message = base.Message
	}
	return delta
}

func sortByName(cases []TestCaseDelta) {
	sort.SliceStable(cases, func(i, j int) bool {
		if cases[i].Suite != cases[j].Suite {
			return cases[i].Suite < cases[j].Suite
		}
		if cases[i].Classname != cases[j].Classname {
			return cases[i].Classname < cases[j].Classname
		}
		return cases[i].Name < cases[j].Name
	})
}

func sortBySlowdown(cases []TestCaseDelta) {
	sort.SliceStable(cases, func(i, j int) bool {
		li, lj := absDuration(cases[i].DurationDelta), absDuration(cases[j].DurationDelta)
		if li != lj {
			return li > lj
		}
		return cases[i].Name < cases[j].Name
	})
}

func absDuration(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
