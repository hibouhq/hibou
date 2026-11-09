package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The tracker mirror (ADR-053 §8): hibou stays the source of truth and mirrors
// each incident into the organisation's trackers — one issue per incident,
// timeline events as comments, state and priority as labels. Inbound changes
// are limited to marking manual actions done and appending notes; nothing
// inbound can set T0, change scope, waive an action or close an incident.

type trackerIssue struct {
	Title  string
	Body   string
	Labels []string
}

type trackerClient interface {
	Create(ctx context.Context, issue trackerIssue) (key, link string, err error)
	Comment(ctx context.Context, key, body string) error
	Update(ctx context.Context, key string, labels []string, closed bool) error
}

type trackerConfig struct {
	BaseURL         string            `json:"base_url"`
	APIURL          string            `json:"api_url"`
	Email           string            `json:"email"`
	Token           string            `json:"token"`
	Auth            string            `json:"auth"`
	ProjectKey      string            `json:"project_key"`
	IssueType       string            `json:"issue_type"`
	CloseTransition string            `json:"close_transition_id"`
	Repository      string            `json:"repository"`
	Project         string            `json:"project"`
	URL             string            `json:"url"`
	Secret          string            `json:"secret"`
	InboundSecret   string            `json:"inbound_secret"`
	StatusMap       map[string]string `json:"status_map"`
	CommentPrefix   string            `json:"comment_prefix"`
}

func openTrackerConfig(integration dbgen.Integration) (trackerConfig, error) {
	var cfg trackerConfig
	opened, err := notify.Secrets().OpenConfig(notify.IntegrationSealContext(integration), integration.Config)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(opened, &cfg)
	return cfg, err
}

func newTrackerClient(integration dbgen.Integration, cfg trackerConfig) (trackerClient, error) {
	httpClient := notify.GuardedHTTPClient(20 * time.Second)
	switch integration.IntegrationType {
	case string(dbgen.IntegrationTypeJira):
		if cfg.BaseURL == "" || cfg.Token == "" || cfg.ProjectKey == "" {
			return nil, errors.New("jira integration requires base_url, token and project_key")
		}
		return &jiraTracker{cfg: cfg, http: httpClient}, nil
	case string(dbgen.IntegrationTypeGithubIssues):
		if cfg.Repository == "" || cfg.Token == "" {
			return nil, errors.New("github_issues integration requires repository and token")
		}
		return &githubTracker{cfg: cfg, http: httpClient}, nil
	case string(dbgen.IntegrationTypeGitlabIssues):
		if cfg.BaseURL == "" || cfg.Project == "" || cfg.Token == "" {
			return nil, errors.New("gitlab_issues integration requires base_url, project and token")
		}
		return &gitlabTracker{cfg: cfg, http: httpClient}, nil
	case string(dbgen.IntegrationTypeTrackerWebhook):
		target := firstNonEmptyString(cfg.URL)
		if target == "" {
			return nil, errors.New("tracker_webhook integration requires url")
		}
		return &webhookTracker{cfg: cfg, http: httpClient}, nil
	}
	return nil, fmt.Errorf("%s is not a tracker", integration.IntegrationType)
}

// trackerRequest sends a JSON request and decodes a JSON answer.
func trackerRequest(ctx context.Context, client *http.Client, method, target string, headers map[string]string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(payload))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("%s %s: HTTP %d %s", method, req.URL.Path, resp.StatusCode, snippet)
	}
	if out != nil && len(payload) > 0 {
		return json.Unmarshal(payload, out)
	}
	return nil
}

type jiraTracker struct {
	cfg  trackerConfig
	http *http.Client
}

func (j *jiraTracker) headers() map[string]string {
	if strings.EqualFold(j.cfg.Auth, "bearer") || j.cfg.Email == "" {
		// Data Center personal access token.
		return map[string]string{"Authorization": "Bearer " + j.cfg.Token}
	}
	// Cloud: e-mail and API token.
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(j.cfg.Email+":"+j.cfg.Token))}
}

func (j *jiraTracker) api(path string) string {
	return strings.TrimRight(j.cfg.BaseURL, "/") + "/rest/api/2" + path
}

func (j *jiraTracker) Create(ctx context.Context, issue trackerIssue) (string, string, error) {
	var created struct {
		Key string `json:"key"`
	}
	body := map[string]any{"fields": map[string]any{
		"project":     map[string]string{"key": j.cfg.ProjectKey},
		"summary":     truncateRunes(issue.Title, 250),
		"description": issue.Body,
		"issuetype":   map[string]string{"name": firstNonEmptyString(j.cfg.IssueType, "Task")},
		"labels":      issue.Labels,
	}}
	if err := trackerRequest(ctx, j.http, http.MethodPost, j.api("/issue"), j.headers(), body, &created); err != nil {
		return "", "", err
	}
	return created.Key, strings.TrimRight(j.cfg.BaseURL, "/") + "/browse/" + created.Key, nil
}

func (j *jiraTracker) Comment(ctx context.Context, key, body string) error {
	return trackerRequest(ctx, j.http, http.MethodPost, j.api("/issue/"+url.PathEscape(key)+"/comment"), j.headers(), map[string]string{"body": body}, nil)
}

func (j *jiraTracker) Update(ctx context.Context, key string, labels []string, closed bool) error {
	if err := trackerRequest(ctx, j.http, http.MethodPut, j.api("/issue/"+url.PathEscape(key)), j.headers(), map[string]any{"fields": map[string]any{"labels": labels}}, nil); err != nil {
		return err
	}
	if closed && j.cfg.CloseTransition != "" {
		return trackerRequest(ctx, j.http, http.MethodPost, j.api("/issue/"+url.PathEscape(key)+"/transitions"), j.headers(), map[string]any{"transition": map[string]string{"id": j.cfg.CloseTransition}}, nil)
	}
	return nil
}

type githubTracker struct {
	cfg  trackerConfig
	http *http.Client
}

func (g *githubTracker) api(path string) string {
	return strings.TrimRight(firstNonEmptyString(g.cfg.APIURL, "https://api.github.com"), "/") + "/repos/" + strings.Trim(g.cfg.Repository, "/") + path
}

func (g *githubTracker) headers() map[string]string {
	return map[string]string{"Authorization": "Bearer " + g.cfg.Token, "X-GitHub-Api-Version": "2022-11-28"}
}

func (g *githubTracker) Create(ctx context.Context, issue trackerIssue) (string, string, error) {
	var created struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := trackerRequest(ctx, g.http, http.MethodPost, g.api("/issues"), g.headers(), map[string]any{"title": issue.Title, "body": issue.Body, "labels": issue.Labels}, &created); err != nil {
		return "", "", err
	}
	return strconv.Itoa(created.Number), created.HTMLURL, nil
}

func (g *githubTracker) Comment(ctx context.Context, key, body string) error {
	return trackerRequest(ctx, g.http, http.MethodPost, g.api("/issues/"+url.PathEscape(key)+"/comments"), g.headers(), map[string]string{"body": body}, nil)
}

func (g *githubTracker) Update(ctx context.Context, key string, labels []string, closed bool) error {
	state := "open"
	if closed {
		state = "closed"
	}
	return trackerRequest(ctx, g.http, http.MethodPatch, g.api("/issues/"+url.PathEscape(key)), g.headers(), map[string]any{"labels": labels, "state": state}, nil)
}

type gitlabTracker struct {
	cfg  trackerConfig
	http *http.Client
}

func (g *gitlabTracker) api(path string) string {
	return strings.TrimRight(g.cfg.BaseURL, "/") + "/api/v4/projects/" + url.PathEscape(g.cfg.Project) + path
}

func (g *gitlabTracker) headers() map[string]string {
	return map[string]string{"PRIVATE-TOKEN": g.cfg.Token}
}

func (g *gitlabTracker) Create(ctx context.Context, issue trackerIssue) (string, string, error) {
	var created struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}
	if err := trackerRequest(ctx, g.http, http.MethodPost, g.api("/issues"), g.headers(), map[string]any{"title": issue.Title, "description": issue.Body, "labels": strings.Join(issue.Labels, ",")}, &created); err != nil {
		return "", "", err
	}
	return strconv.Itoa(created.IID), created.WebURL, nil
}

func (g *gitlabTracker) Comment(ctx context.Context, key, body string) error {
	return trackerRequest(ctx, g.http, http.MethodPost, g.api("/issues/"+url.PathEscape(key)+"/notes"), g.headers(), map[string]string{"body": body}, nil)
}

func (g *gitlabTracker) Update(ctx context.Context, key string, labels []string, closed bool) error {
	event := "reopen"
	if closed {
		event = "close"
	}
	return trackerRequest(ctx, g.http, http.MethodPut, g.api("/issues/"+url.PathEscape(key)), g.headers(), map[string]any{"labels": strings.Join(labels, ","), "state_event": event}, nil)
}

// webhookTracker POSTs signed JSON for any other tracker; the key is the
// incident id.
type webhookTracker struct {
	cfg  trackerConfig
	http *http.Client
	key  string
}

func (w *webhookTracker) post(ctx context.Context, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.Secret != "" {
		notify.SignWebhookRequest(req, []byte(w.cfg.Secret), body, time.Now())
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("tracker webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func (w *webhookTracker) Create(ctx context.Context, issue trackerIssue) (string, string, error) {
	return w.key, "", w.post(ctx, map[string]any{"event": "incident.created", "key": w.key, "title": issue.Title, "body": issue.Body, "labels": issue.Labels})
}

func (w *webhookTracker) Comment(ctx context.Context, key, body string) error {
	return w.post(ctx, map[string]any{"event": "incident.comment", "key": key, "body": body})
}

func (w *webhookTracker) Update(ctx context.Context, key string, labels []string, closed bool) error {
	return w.post(ctx, map[string]any{"event": "incident.updated", "key": key, "labels": labels, "closed": closed})
}

func incidentTrackerLabels(inc dbgen.Incident) []string {
	labels := []string{"hibou", "hibou-incident", "hibou-" + strings.ReplaceAll(inc.Kind, "_", "-"), "hibou-state-" + strings.ReplaceAll(string(inc.State), "_", "-"), "hibou-" + strings.ToLower(inc.Priority)}
	sort.Strings(labels)
	return labels
}

func (s *Server) incidentIssueBody(ctx context.Context, inc dbgen.Incident) string {
	var b strings.Builder
	link := s.incidentLink(ctx, inc)
	if base := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/"); base != "" && link != "" {
		link = base + link
	}
	fmt.Fprintf(&b, "Mirrored from hibou — the incident there is the source of truth: %s\n\n", link)
	fmt.Fprintf(&b, "Kind: %s\nState: %s\nPriority: %s\nRegimes: %s\nSignal: %s at %s\n", incident.KindLabel(inc.Kind), inc.State, inc.Priority, strings.Join(inc.Regimes, ", "), inc.SignalSource, inc.SignalAt.UTC().Format(time.RFC3339))
	if inc.AwareAt.Valid {
		fmt.Fprintf(&b, "Aware (T0): %s\n", inc.AwareAt.Time.UTC().Format(time.RFC3339))
	}
	if scope, err := s.queries.Incidents().ListIncidentScope(ctx, inc.ID); err == nil && len(scope) > 0 {
		b.WriteString("\nScope:\n")
		for _, row := range scope {
			fmt.Fprintf(&b, "- %s %s: %s\n", row.SubjectType, row.Label, row.Status)
		}
	}
	if actions, err := s.queries.Incidents().ListIncidentActions(ctx, inc.ID); err == nil && len(actions) > 0 {
		b.WriteString("\nActions:\n")
		for _, action := range actions {
			if action.Obsolete {
				continue
			}
			due := ""
			if action.DueAt.Valid {
				due = " (due " + action.DueAt.Time.UTC().Format(time.RFC3339) + ")"
			}
			fmt.Fprintf(&b, "- [%s] %s%s\n", map[bool]string{true: "x", false: " "}[action.State != "pending"], action.Label, due)
		}
	}
	return b.String()
}

func incidentEventLine(event dbgen.IncidentEvent) string {
	var detail map[string]any
	_ = json.Unmarshal(event.Detail, &detail)
	var summary strings.Builder
	for _, key := range []string{"label", "reason", "text", "state", "reference", "client", "status"} {
		if value, ok := detail[key].(string); ok && value != "" {
			summary.WriteString(" " + key + ": " + value + ";")
		}
	}
	return fmt.Sprintf("%s — %s by %s.%s", event.At.UTC().Format(time.RFC3339), event.Kind, firstNonEmptyString(event.ActorDisplay, event.ActorType), strings.TrimSuffix(summary.String(), ";"))
}

// syncIncidentTrackers mirrors one incident into every enabled tracker of its
// organisation. Failures are integration-health facts, never blockers.
func (s *Server) syncIncidentTrackers(ctx context.Context, incidentID uuid.UUID) {
	db := s.queries.Incidents()
	inc, err := db.GetIncident(ctx, incidentID)
	if err != nil {
		return
	}
	trackers, err := db.ListOrgTrackerIntegrations(ctx, inc.OrgID)
	if err != nil || len(trackers) == 0 {
		return
	}
	links, _ := db.ListIncidentTrackerLinks(ctx, incidentID)
	linkByIntegration := map[uuid.UUID]dbgen.ListIncidentTrackerLinksRow{}
	for _, link := range links {
		linkByIntegration[link.IntegrationID] = link
	}
	eventsList, err := db.ListIncidentEvents(ctx, incidentID)
	if err != nil {
		return
	}
	closed := !incident.Open(string(inc.State))
	for _, integration := range trackers {
		link, linked := linkByIntegration[integration.ID]
		cfg, err := openTrackerConfig(integration)
		var client trackerClient
		if err == nil {
			client, err = newTrackerClient(integration, cfg)
		}
		if webhook, ok := client.(*webhookTracker); ok {
			webhook.key = inc.ID.String()
		}
		synced := int32(0)
		key, link_ := "", ""
		if linked {
			synced, key, link_ = link.SyncedEvents, link.ExternalKey, link.ExternalUrl
		}
		if err == nil && key == "" {
			key, link_, err = client.Create(ctx, trackerIssue{Title: fmt.Sprintf("[hibou #%d] %s", inc.Number, inc.Title), Body: s.incidentIssueBody(ctx, inc), Labels: incidentTrackerLabels(inc)})
			if err == nil {
				synced = int32(len(eventsList)) // #nosec G115 -- bounded by an incident's timeline
			}
		}
		if err == nil && int(synced) < len(eventsList) {
			lines := []string{}
			for _, event := range eventsList[synced:] {
				if event.ActorType == "tracker" {
					continue // never echo what came from the tracker
				}
				lines = append(lines, incidentEventLine(event))
			}
			if len(lines) > 0 {
				err = client.Comment(ctx, key, strings.Join(lines, "\n"))
			}
			if err == nil {
				synced = int32(len(eventsList)) // #nosec G115 -- bounded by an incident's timeline
			}
		}
		if err == nil {
			err = client.Update(ctx, key, incidentTrackerLabels(inc), closed)
		}
		lastError := ""
		if err != nil {
			lastError = truncateRunes(err.Error(), 500)
			if !linked || link.LastError == "" {
				s.publishIncidentEvent(ctx, events.IncidentMirrorLagging, inc, fmt.Sprintf("Incident #%d: %s mirror lagging", inc.Number, integration.Name), lastError)
			}
		}
		_ = db.UpsertIncidentTrackerLink(ctx, dbgen.UpsertIncidentTrackerLinkParams{
			IncidentID: inc.ID, IntegrationID: integration.ID, ExternalKey: key, ExternalUrl: link_, SyncedEvents: synced,
			LastSyncedAt: nullTimeNow(err == nil), LastError: lastError,
		})
	}
}

func nullTimeNow(valid bool) sql.NullTime {
	return sql.NullTime{Time: time.Now().UTC(), Valid: valid}
}

// handleIncidentTrackerWebhook takes the inbound half of the mirror. The
// shared secret authorises it; what it can do is bounded: complete pending
// manual actions mapped from a tracker status, and append prefixed comments
// as notes.
func (s *Server) handleIncidentTrackerWebhook(w http.ResponseWriter, r *http.Request) {
	integrationID, err := uuid.Parse(chi.URLParam(r, "integrationID"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	integration, err := s.queries.GetIntegrationByID(r.Context(), integrationID)
	if err != nil || integration == nil || !integration.Enabled {
		http.NotFound(w, r)
		return
	}
	cfg, err := openTrackerConfig(*integration)
	if err != nil || cfg.InboundSecret == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if !trackerInboundAuthorized(r, body, cfg.InboundSecret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	update := parseTrackerInbound(integration.IntegrationType, body)
	if update.key == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	incidentID, err := s.queries.Incidents().FindIncidentByTrackerKey(r.Context(), dbgen.FindIncidentByTrackerKeyParams{IntegrationID: integration.ID, ExternalKey: update.key})
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	inc, err := s.queries.Incidents().GetIncident(r.Context(), incidentID)
	if err != nil || inc.OrgID != integration.OrgID {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	actor := incidentActor{Type: "tracker", Display: firstNonEmptyString(update.author, integration.Name)}
	prefix := firstNonEmptyString(cfg.CommentPrefix, "hibou:")
	if text, ok := strings.CutPrefix(strings.TrimSpace(update.comment), prefix); ok && strings.TrimSpace(text) != "" {
		s.appendIncidentEvent(r.Context(), s.queries.Incidents(), inc.ID, actor, "note", map[string]any{"text": strings.TrimSpace(text), "tracker": integration.Name})
	}
	if kind, ok := cfg.StatusMap[update.status]; ok && update.status != "" {
		actions, err := s.queries.Incidents().ListIncidentActions(r.Context(), inc.ID)
		if err == nil {
			for _, action := range actions {
				if action.Kind != kind || action.State != "pending" || action.Automatic || action.Obsolete {
					continue
				}
				if _, _, isFiling := filingStep(inc, action.Kind, nil); isFiling {
					continue // a filing needs the platform reference, recorded in hibou
				}
				evidence, _ := json.Marshal(map[string]any{"tracker": integration.Name, "key": update.key, "status": update.status})
				if _, err := s.queries.Incidents().CompleteIncidentAction(r.Context(), dbgen.CompleteIncidentActionParams{ID: action.ID, IncidentID: inc.ID, Evidence: evidence}); err == nil {
					s.appendIncidentEvent(r.Context(), s.queries.Incidents(), inc.ID, actor, "action.completed", map[string]any{"action_id": action.ID, "kind": action.Kind, "label": action.Label, "tracker_status": update.status})
				}
			}
		}
		s.queueIncidentReconcile(inc.ID)
	}
	w.WriteHeader(http.StatusAccepted)
}

type trackerInbound struct {
	key, status, comment, author string
}

func parseTrackerInbound(kind string, body []byte) trackerInbound {
	var out trackerInbound
	switch kind {
	case string(dbgen.IntegrationTypeJira):
		var payload struct {
			Issue struct {
				Key    string `json:"key"`
				Fields struct {
					Status struct {
						Name string `json:"name"`
					} `json:"status"`
				} `json:"fields"`
			} `json:"issue"`
			Comment struct {
				Body   string `json:"body"`
				Author struct {
					DisplayName string `json:"displayName"`
				} `json:"author"`
			} `json:"comment"`
			User struct {
				DisplayName string `json:"displayName"`
			} `json:"user"`
		}
		if json.Unmarshal(body, &payload) == nil {
			out = trackerInbound{key: payload.Issue.Key, status: payload.Issue.Fields.Status.Name, comment: payload.Comment.Body, author: firstNonEmptyString(payload.Comment.Author.DisplayName, payload.User.DisplayName)}
		}
	case string(dbgen.IntegrationTypeGithubIssues):
		var payload struct {
			Action string `json:"action"`
			Issue  struct {
				Number int `json:"number"`
			} `json:"issue"`
			Comment struct {
				Body string `json:"body"`
				User struct {
					Login string `json:"login"`
				} `json:"user"`
			} `json:"comment"`
			Label struct {
				Name string `json:"name"`
			} `json:"label"`
			Sender struct {
				Login string `json:"login"`
			} `json:"sender"`
		}
		if json.Unmarshal(body, &payload) == nil && payload.Issue.Number > 0 {
			status := payload.Action
			if payload.Action == "labeled" {
				status = "label:" + payload.Label.Name
			}
			out = trackerInbound{key: strconv.Itoa(payload.Issue.Number), status: status, comment: payload.Comment.Body, author: firstNonEmptyString(payload.Comment.User.Login, payload.Sender.Login)}
		}
	case string(dbgen.IntegrationTypeGitlabIssues):
		var payload struct {
			ObjectKind       string `json:"object_kind"`
			ObjectAttributes struct {
				IID    int    `json:"iid"`
				Note   string `json:"note"`
				State  string `json:"state"`
				Action string `json:"action"`
			} `json:"object_attributes"`
			Issue struct {
				IID int `json:"iid"`
			} `json:"issue"`
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		}
		if json.Unmarshal(body, &payload) == nil {
			iid := payload.ObjectAttributes.IID
			if payload.ObjectKind == "note" {
				iid = payload.Issue.IID
				out.comment = payload.ObjectAttributes.Note
			} else {
				out.status = firstNonEmptyString(payload.ObjectAttributes.Action, payload.ObjectAttributes.State)
			}
			if iid > 0 {
				out.key = strconv.Itoa(iid)
			}
			out.author = payload.User.Name
		}
	default:
		var payload struct {
			Key     string `json:"key"`
			Status  string `json:"status"`
			Comment string `json:"comment"`
			Author  string `json:"author"`
		}
		if json.Unmarshal(body, &payload) == nil {
			out = trackerInbound{key: payload.Key, status: payload.Status, comment: payload.Comment, author: payload.Author}
		}
	}
	return out
}

// trackerInboundAuthorized accepts a GitHub HMAC signature, a GitLab token
// header, or a shared secret in X-Hibou-Tracker-Secret or ?secret= (what Jira
// webhooks can carry).
func trackerInboundAuthorized(r *http.Request, body []byte, secret string) bool {
	if signature := r.Header.Get("X-Hub-Signature-256"); signature != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		return hmac.Equal([]byte(signature), []byte("sha256="+hex.EncodeToString(mac.Sum(nil))))
	}
	for _, candidate := range []string{r.Header.Get("X-Gitlab-Token"), r.Header.Get("X-Hibou-Tracker-Secret"), r.URL.Query().Get("secret")} {
		if candidate != "" && hmac.Equal([]byte(candidate), []byte(secret)) {
			return true
		}
	}
	return false
}
