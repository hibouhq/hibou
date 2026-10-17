// Package packagepolicy answers "may this package version be used?" from
// hibou's stored package signals, the organisation's cooldown window, the
// private namespace rules and the recorded acceptances (ADR-048 §3–4, §7).
// It is the one evaluator behind the policy endpoint that registry proxies
// call, the MCP tool agents call, and the cooldown gate.
//
// Decisions never require a live lookup on the request path when the
// signal is already stored; a version nobody has seen yet is looked up on
// demand, once, with callers of the same purl waiting on the same flight.
package packagepolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/store"
)

// Decision values.
const (
	DecisionAllow = "allow"
	DecisionHold  = "hold"
	DecisionDeny  = "deny"
)

// Decision is the answer for one purl.
type Decision struct {
	Purl     string `json:"purl"`
	Decision string `json:"decision"`
	// Until is set on a hold: the cooldown end under the applied window.
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason"`
	// Evaluated is false when nothing could be said: unsupported
	// ecosystem, private namespace, provider disabled or unreachable.
	// The decision is then allow, and the reason says why.
	Evaluated bool `json:"evaluated"`
	// Warnings carry what does not change the decision: deprecated, low
	// usage with alternatives, unpublished.
	Warnings []string `json:"warnings,omitempty"`
	// Accepted is true when an acceptance turned a hold or deny into allow.
	Accepted bool `json:"accepted,omitempty"`
	// Signals are the stored signals, when any.
	Signals *Signals `json:"signals,omitempty"`
}

// Signals is the subset of stored signals the decision was made on.
type Signals struct {
	PublishedAt        *time.Time `json:"published_at,omitempty"`
	CooldownEnd        *time.Time `json:"cooldown_end,omitempty"`
	Deprecated         bool       `json:"deprecated,omitempty"`
	DeprecatedReason   string     `json:"deprecated_reason,omitempty"`
	LowUsage           bool       `json:"low_usage,omitempty"`
	Alternatives       []string   `json:"alternatives,omitempty"`
	Unpublished        bool       `json:"unpublished,omitempty"`
	Malicious          bool       `json:"malicious,omitempty"`
	RecommendedVersion string     `json:"recommended_version,omitempty"`
	FetchedAt          time.Time  `json:"fetched_at"`
}

// Policy is the effective policy for one request: the organisation's
// defaults narrowed by the repository's .hibou.yaml (stricter only).
type Policy struct {
	// Window: auto, off, or a duration counted from the publish date.
	WindowMode     string
	WindowDuration time.Duration
	// PrivateNamespaces are never looked up or sent anywhere.
	PrivateNamespaces []string
}

// Request is one evaluation.
type Request struct {
	OrgID uuid.UUID
	// RepoID scopes acceptances; nil means org-wide only.
	RepoID *uuid.UUID
	Purls  []string
	Policy Policy
	// Now is the evaluation instant (tests pass a fixed one).
	Now time.Time
}

// Store is what the evaluator reads and writes.
type Store interface {
	GetPackageSignalsByPurls(ctx context.Context, purls []string) (map[string]store.PackageSignal, error)
	UpsertPackageSignals(ctx context.Context, signals []depsdev.Signals) error
	ListPackagePolicyAcceptancesForPurls(ctx context.Context, orgID uuid.UUID, repoID *uuid.UUID, purls []string) ([]store.PackagePolicyAcceptance, error)
}

// Lookup is the on-demand provider; nil when deps.dev is switched off.
type Lookup interface {
	FindingsBatch(ctx context.Context, keys []depsdev.VersionKey) (map[depsdev.VersionKey]depsdev.FindingsResult, error)
	VersionBatch(ctx context.Context, purls []string) (map[string]*depsdev.VersionInfo, error)
}

// Evaluator evaluates requests.
type Evaluator struct {
	store  Store
	lookup Lookup
	// freshFor is how long a stored signal is trusted before a lookup.
	freshFor time.Duration
	// instanceNamespaces are the operator's private namespaces, applied on
	// top of the request's.
	instanceNamespaces []string
	// defaultWindow is the instance default when the request gives none.
	defaultWindow string

	mu       sync.Mutex
	inflight map[string]chan struct{}
}

// Options configure an evaluator.
type Options struct {
	Lookup             Lookup
	FreshFor           time.Duration
	InstanceNamespaces []string
	// DefaultWindow is auto unless set.
	DefaultWindow string
}

// New returns an evaluator over st.
func New(st Store, opts Options) *Evaluator {
	freshFor := opts.FreshFor
	if freshFor <= 0 {
		freshFor = 24 * time.Hour
	}
	window := strings.TrimSpace(opts.DefaultWindow)
	if window == "" {
		window = cooldown.WindowAuto
	}
	return &Evaluator{
		store:              st,
		lookup:             opts.Lookup,
		freshFor:           freshFor,
		instanceNamespaces: opts.InstanceNamespaces,
		defaultWindow:      window,
		inflight:           make(map[string]chan struct{}),
	}
}

// DefaultPolicy is the instance policy: the configured window and private
// namespaces, with no repository override.
func (e *Evaluator) DefaultPolicy() Policy {
	return e.PolicyWith("", nil)
}

// PolicyWith narrows the instance default with a repository's window and
// private namespaces (ADR-035's resolution order says a repository may be
// stricter than its organisation; until organisation policy exists the
// repository's value applies as written).
func (e *Evaluator) PolicyWith(window string, privateNamespaces []string) Policy {
	policy := Policy{WindowMode: cooldown.WindowAuto}
	if mode, duration, ok, err := cooldown.ParseWindow(e.defaultWindow); err == nil && ok {
		policy.WindowMode, policy.WindowDuration = mode, duration
	}
	if mode, duration, ok, err := cooldown.ParseWindow(window); err == nil && ok {
		policy.WindowMode, policy.WindowDuration = mode, duration
	}
	policy.PrivateNamespaces = append(policy.PrivateNamespaces, privateNamespaces...)
	return policy
}

// Evaluate answers every purl in the request, in the request's order.
func (e *Evaluator) Evaluate(ctx context.Context, req Request) ([]Decision, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	decisions := make([]Decision, len(req.Purls))
	namespaces := append(append([]string{}, e.instanceNamespaces...), req.Policy.PrivateNamespaces...)

	type pending struct {
		index     int
		key       depsdev.VersionKey
		canonical string
	}
	var evaluable []pending
	for i, purl := range req.Purls {
		purl = strings.TrimSpace(purl)
		decisions[i] = Decision{Purl: purl, Decision: DecisionAllow}
		if purl == "" {
			decisions[i].Reason = "empty package URL"
			continue
		}
		if depsdev.IsPrivate(purl, namespaces) {
			decisions[i].Reason = "private namespace: not evaluated, never sent to a third party"
			continue
		}
		key, canonical, ok := depsdev.ParsePurl(purl)
		if !ok {
			decisions[i].Reason = "ecosystem not covered by package signals"
			continue
		}
		evaluable = append(evaluable, pending{index: i, key: key, canonical: canonical})
	}
	if len(evaluable) == 0 {
		return decisions, nil
	}

	purls := make([]string, 0, len(evaluable))
	for _, p := range evaluable {
		purls = append(purls, decisions[p.index].Purl)
	}
	signals, err := e.store.GetPackageSignalsByPurls(ctx, purls)
	if err != nil {
		return nil, fmt.Errorf("packagepolicy: load signals: %w", err)
	}
	acceptances, err := e.store.ListPackagePolicyAcceptancesForPurls(ctx, req.OrgID, req.RepoID, purls)
	if err != nil {
		return nil, fmt.Errorf("packagepolicy: load acceptances: %w", err)
	}
	accepted := make(map[string]store.PackagePolicyAcceptance, len(acceptances))
	for _, acceptance := range acceptances {
		// A repository row is more specific than an org-wide one.
		if existing, ok := accepted[acceptance.Purl]; ok && existing.RepoID != nil && acceptance.RepoID == nil {
			continue
		}
		accepted[acceptance.Purl] = acceptance
	}

	// Look up what is missing or stale, once per purl across callers.
	var missing []pending
	for _, p := range evaluable {
		row, ok := signals[decisions[p.index].Purl]
		if !ok || now.Sub(row.FetchedAt) > e.freshFor {
			missing = append(missing, p)
		}
	}
	lookupErr := ""
	if len(missing) > 0 && e.lookup != nil {
		keys := make([]depsdev.VersionKey, 0, len(missing))
		canonicals := make([]string, 0, len(missing))
		purlByCanonical := make(map[string]string, len(missing))
		for _, p := range missing {
			purl := decisions[p.index].Purl
			if _, dup := purlByCanonical[p.canonical]; dup {
				continue
			}
			purlByCanonical[p.canonical] = purl
			keys = append(keys, p.key)
			canonicals = append(canonicals, p.canonical)
		}
		fetched, err := e.lookupOnce(ctx, keys, canonicals, purlByCanonical, now)
		if err != nil {
			lookupErr = err.Error()
		}
		for purl, row := range fetched {
			signals[purl] = row
		}
		// Spellings that share a canonical purl share the answer.
		for _, p := range missing {
			purl := decisions[p.index].Purl
			if _, ok := signals[purl]; ok {
				continue
			}
			if row, ok := signals[purlByCanonical[p.canonical]]; ok {
				signals[purl] = row
			}
		}
	}

	for _, p := range evaluable {
		decision := &decisions[p.index]
		row, ok := signals[decision.Purl]
		if !ok {
			decision.Evaluated = false
			switch {
			case e.lookup == nil:
				decision.Reason = "package signals are disabled on this instance: not evaluated"
			case lookupErr != "":
				decision.Reason = "package signals unavailable: not evaluated (" + lookupErr + ")"
			default:
				decision.Reason = "no signal known for this version: not evaluated"
			}
			continue
		}
		*decision = decide(decision.Purl, row, req.Policy, now)
		if acceptance, ok := accepted[decision.Purl]; ok && decision.Decision != DecisionAllow {
			decision.Decision = DecisionAllow
			decision.Accepted = true
			decision.Until = nil
			scope := "organization"
			if acceptance.RepoID != nil {
				scope = "repository"
			}
			decision.Reason = fmt.Sprintf("accepted for this %s: %s", scope, acceptance.Reason)
		}
	}
	return decisions, nil
}

// decide applies the policy to one stored row.
func decide(purl string, row store.PackageSignal, policy Policy, now time.Time) Decision {
	decision := Decision{Purl: purl, Decision: DecisionAllow, Evaluated: true, Signals: signalsFromRow(row)}
	if row.Malicious {
		decision.Decision = DecisionDeny
		decision.Reason = "flagged as malicious by the OpenSSF Malicious Packages project"
		return decision
	}
	if row.NotFound {
		decision.Warnings = append(decision.Warnings, "unpublished: this version is no longer on the public registry")
	}
	if row.Deprecated {
		reason := strings.TrimSpace(row.DeprecatedReason)
		if reason == "" {
			reason = "deprecated on the registry"
		} else {
			reason = "deprecated: " + reason
		}
		decision.Warnings = append(decision.Warnings, reason)
	}
	if row.LowUsage {
		warning := "low usage: verify this is the package you meant"
		if alternatives := decision.Signals.Alternatives; len(alternatives) > 0 {
			warning = "low usage: did you mean " + strings.Join(alternatives, ", ") + "?"
		}
		decision.Warnings = append(decision.Warnings, warning)
	}

	var end *time.Time
	switch policy.WindowMode {
	case cooldown.WindowOff:
	case cooldown.WindowDuration:
		if row.PublishedAt.Valid {
			until := row.PublishedAt.Time.Add(policy.WindowDuration)
			end = &until
		}
	default: // auto
		if row.CooldownEnd.Valid {
			until := row.CooldownEnd.Time
			end = &until
		}
	}
	if end != nil && end.After(now) {
		decision.Decision = DecisionHold
		until := end.UTC()
		decision.Until = &until
		published := ""
		if row.PublishedAt.Valid {
			published = ", published " + row.PublishedAt.Time.UTC().Format("2006-01-02")
		}
		if policy.WindowMode == cooldown.WindowDuration {
			decision.Reason = fmt.Sprintf("in cooldown until %s (%s window%s)", until.Format("2006-01-02"), policy.WindowDuration, published)
		} else {
			decision.Reason = fmt.Sprintf("in cooldown until %s (deps.dev recommends waiting%s)", until.Format("2006-01-02"), published)
		}
		return decision
	}
	decision.Reason = "no hold"
	if len(decision.Warnings) > 0 {
		decision.Reason = "allowed with warnings"
	}
	return decision
}

func signalsFromRow(row store.PackageSignal) *Signals {
	out := &Signals{
		Deprecated:         row.Deprecated,
		DeprecatedReason:   row.DeprecatedReason,
		LowUsage:           row.LowUsage,
		Unpublished:        row.NotFound,
		Malicious:          row.Malicious,
		RecommendedVersion: row.RecommendedVersion,
		FetchedAt:          row.FetchedAt,
	}
	if row.PublishedAt.Valid {
		t := row.PublishedAt.Time.UTC()
		out.PublishedAt = &t
	}
	if row.CooldownEnd.Valid {
		t := row.CooldownEnd.Time.UTC()
		out.CooldownEnd = &t
	}
	if len(row.Alternatives) > 0 {
		var alternatives []string
		if err := unmarshalStrings(row.Alternatives, &alternatives); err == nil {
			out.Alternatives = alternatives
		}
	}
	return out
}

// lookupOnce fetches the keys from the provider and stores the result.
// Callers racing on the same purls wait for the first flight instead of
// each calling the provider.
func (e *Evaluator) lookupOnce(ctx context.Context, keys []depsdev.VersionKey, canonicals []string, purlByCanonical map[string]string, now time.Time) (map[string]store.PackageSignal, error) {
	// Wait for in-flight lookups of any of our purls, then claim the rest.
	waitFor := make([]chan struct{}, 0)
	mine := make([]int, 0, len(canonicals))
	e.mu.Lock()
	for i, canonical := range canonicals {
		if ch, busy := e.inflight[canonical]; busy {
			waitFor = append(waitFor, ch)
			continue
		}
		e.inflight[canonical] = make(chan struct{})
		mine = append(mine, i)
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		for _, i := range mine {
			if ch, ok := e.inflight[canonicals[i]]; ok {
				close(ch)
				delete(e.inflight, canonicals[i])
			}
		}
		e.mu.Unlock()
	}()
	for _, ch := range waitFor {
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	out := make(map[string]store.PackageSignal)
	if len(mine) == 0 {
		// Everything we needed was fetched by another flight: read it back.
		purls := make([]string, 0, len(canonicals))
		for _, canonical := range canonicals {
			purls = append(purls, purlByCanonical[canonical])
		}
		rows, err := e.store.GetPackageSignalsByPurls(ctx, purls)
		if err != nil {
			return nil, err
		}
		return rows, nil
	}
	myKeys := make([]depsdev.VersionKey, 0, len(mine))
	myCanonicals := make([]string, 0, len(mine))
	for _, i := range mine {
		myKeys = append(myKeys, keys[i])
		myCanonicals = append(myCanonicals, canonicals[i])
	}
	findings, err := e.lookup.FindingsBatch(ctx, myKeys)
	if err != nil {
		return nil, err
	}
	infos, err := e.lookup.VersionBatch(ctx, myCanonicals)
	if err != nil {
		return nil, err
	}
	signals := make([]depsdev.Signals, 0, len(mine))
	for _, i := range mine {
		purl := purlByCanonical[canonicals[i]]
		var f *depsdev.FindingsResult
		if result, ok := findings[keys[i]]; ok {
			f = &result
		}
		info := infos[canonicals[i]]
		if f == nil && info == nil {
			continue
		}
		signals = append(signals, depsdev.Normalize(purl, keys[i], f, info, now))
	}
	if err := e.store.UpsertPackageSignals(ctx, signals); err != nil {
		return nil, err
	}
	fetched, err := e.store.GetPackageSignalsByPurls(ctx, purlsOf(signals))
	if err != nil {
		return nil, err
	}
	for purl, row := range fetched {
		out[purl] = row
	}
	if len(waitFor) > 0 {
		// Add what the other flights stored.
		purls := make([]string, 0, len(canonicals))
		for _, canonical := range canonicals {
			purls = append(purls, purlByCanonical[canonical])
		}
		rows, err := e.store.GetPackageSignalsByPurls(ctx, purls)
		if err == nil {
			for purl, row := range rows {
				if _, ok := out[purl]; !ok {
					out[purl] = row
				}
			}
		}
	}
	return out, nil
}

func purlsOf(signals []depsdev.Signals) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		out = append(out, s.Purl)
	}
	sort.Strings(out)
	return out
}

// ErrNoStore is returned when an evaluator was built without a store.
var ErrNoStore = errors.New("packagepolicy: no store")
