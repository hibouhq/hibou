package depsdev

// HealthSettingKey is the instance setting holding the last pass's
// summary, same contract as the KEV and EPSS records: "no signals" and
// "never synced" must never look alike. Shared with the seed so a dev
// instance shows a plausible card.
const HealthSettingKey = "depsdev_last_sync"

// Health is the stored summary of the most recent package-signals pass.
type Health struct {
	// At is when the loop last completed a pass, successful or not.
	At string `json:"at"`
	// SucceededAt is the last pass that finished without an API error.
	SucceededAt     string `json:"succeeded_at,omitempty"`
	DurationMillis  int64  `json:"duration_ms,omitempty"`
	Candidates      int    `json:"candidates,omitempty"`
	Private         int    `json:"private,omitempty"`
	Unsupported     int    `json:"unsupported,omitempty"`
	LookedUp        int    `json:"looked_up,omitempty"`
	Stored          int64  `json:"stored,omitempty"`
	Error           string `json:"error,omitempty"`
	FailingSince    string `json:"failing_since,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	URL             string `json:"url,omitempty"`
}
