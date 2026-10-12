package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/ws"
)

const maxAnnouncementBanners = 10

var bannerColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// instanceAdminState tracks the last-resolved admin list so external edits to
// the source (a Secret-mounted file) can be detected and audit-logged.
type instanceAdminState struct {
	mu      sync.Mutex
	current []string
	loaded  bool
}

// instanceAdminEmails resolves the current instance-admin list. When
// HIBOU_INSTANCE_ADMINS_FILE is set the file is re-read on every call, so a
// Secret mounted as a volume takes effect within the kubelet sync period —
// no restart, no email in git or Helm values. Falls back to the env list, and
// on a transient read error to the last successfully loaded list (an
// unreadable file must not lock every admin out — or, worse, silently keep
// them in on an intentional wipe; the previous list is the safest state).
// List changes are diffed and audit-logged (see recordInstanceAdminChanges).
func (s *Server) instanceAdminEmails(ctx context.Context) []string {
	emails := s.cfg.InstanceAdmins
	if s.cfg.InstanceAdminsFile != "" {
		raw, err := os.ReadFile(s.cfg.InstanceAdminsFile)
		if err == nil {
			emails = config.ParseEmailList(string(raw))
		} else {
			s.instanceAdmins.mu.Lock()
			loaded := s.instanceAdmins.loaded
			previous := append([]string(nil), s.instanceAdmins.current...)
			s.instanceAdmins.mu.Unlock()
			if loaded {
				s.log.Warn().Err(err).Str("path", s.cfg.InstanceAdminsFile).Msg("instance admins file unreadable; keeping last loaded list")
				return previous
			}
			s.log.Warn().Err(err).Str("path", s.cfg.InstanceAdminsFile).Msg("instance admins file unreadable; falling back to HIBOU_INSTANCE_ADMINS")
		}
	}
	s.recordInstanceAdminChanges(ctx, emails)
	return emails
}

// recordInstanceAdminChanges diffs the resolved list against the last seen one
// and writes grant/revoke audit rows. The list is managed outside the app
// (Secret/env), so detection at read time is the only interception point. The
// first resolution after startup sets the baseline silently — restarts must
// not re-audit the whole list. With multiple replicas each may record the same
// change once; duplicate system-actor rows are preferable to missing ones.
func (s *Server) recordInstanceAdminChanges(ctx context.Context, emails []string) {
	s.instanceAdmins.mu.Lock()
	defer s.instanceAdmins.mu.Unlock()

	if !s.instanceAdmins.loaded {
		s.instanceAdmins.current = append([]string(nil), emails...)
		s.instanceAdmins.loaded = true
		return
	}

	previous := make(map[string]struct{}, len(s.instanceAdmins.current))
	for _, email := range s.instanceAdmins.current {
		previous[email] = struct{}{}
	}
	next := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		next[email] = struct{}{}
	}

	for email := range next {
		if _, ok := previous[email]; !ok {
			s.writeInstanceAdminAudit(ctx, "instance.admin.granted", email)
		}
	}
	for email := range previous {
		if _, ok := next[email]; !ok {
			s.writeInstanceAdminAudit(ctx, "instance.admin.revoked", email)
		}
	}
	s.instanceAdmins.current = append([]string(nil), emails...)
}

func (s *Server) writeInstanceAdminAudit(ctx context.Context, action, email string) {
	if s.queries == nil {
		return
	}
	encoded, err := json.Marshal(map[string]any{"email": email, "source": "instance-admins-config"})
	if err != nil {
		encoded = json.RawMessage(`{}`)
	}
	if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "instance-admins-watcher",
		Action:       action,
		ResourceType: "instance_admin",
		ResourceID:   email,
		OrgID:        uuid.NullUUID{},
		Context:      encoded,
	}); err != nil {
		s.log.Warn().Err(err).Str("action", action).Str("email", email).Msg("instance admin audit write failed")
	}
}

// runInstanceAdminWatchLoop re-resolves the admin list periodically so list
// changes are audit-logged near the time they happen, even with no admin
// traffic. Request-time resolution catches them too; this is the floor.
func (s *Server) runInstanceAdminWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	s.instanceAdminEmails(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.instanceAdminEmails(ctx)
		}
	}
}

// isInstanceAdmin reports whether the session user is a hibou instance
// administrator. Instance admin is an instance-level role, distinct from org
// and repo admin membership; service principals never qualify.
func (s *Server) isInstanceAdmin(r *http.Request) bool {
	return s.userIsInstanceAdmin(UserFromContext(r.Context()), s.instanceAdminEmails(r.Context()))
}

// userIsInstanceAdmin matches a user against the admin list. A
// "provider:provider_id" entry (e.g. "github:1234567") binds the immutable
// forge account and is the recommended form. A bare email entry is honored
// only for accounts whose provider verifies the email it reports: anyone can
// set an unverified address on a self-hosted forge profile.
func (s *Server) userIsInstanceAdmin(user *store.User, entries []string) bool {
	if user == nil {
		return false
	}
	identity := strings.ToLower(strings.TrimSpace(user.Provider)) + ":" + strings.ToLower(strings.TrimSpace(user.ProviderID))
	email := strings.ToLower(strings.TrimSpace(user.Email))
	emailTrusted := email != "" && s.providerVerifiesEmail(user.Provider)
	for _, entry := range entries {
		if strings.Contains(entry, "@") {
			if emailTrusted && entry == email {
				return true
			}
			continue
		}
		if strings.TrimSpace(user.ProviderID) != "" && entry == identity {
			return true
		}
	}
	return false
}

// providerVerifiesEmail reports whether a provider only ever hands hibou a
// verified email. GitHub does (public email or a verified one from
// /user/emails); GitLab and Forgejo report the profile email unchecked. The
// development login's local account counts in development only.
func (s *Server) providerVerifiesEmail(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "github":
		return true
	case "local":
		return s.cfg.IsDevelopment()
	default:
		return false
	}
}

// @Summary      Instance administrators
// @Description  The current instance-admin email list, resolved live from its managed source (Secret-mounted file or env). Instance admins only.
// @Tags         instance
// @Produce      json
// @Success      200  {object}  api.Response{data=[]string}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/settings/admins [get]
func (s *Server) handleListInstanceAdmins(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return
	}
	admins := append([]string(nil), s.instanceAdminEmails(r.Context())...)
	sort.Strings(admins)
	api.JSON(w, http.StatusOK, admins)
}

// @Summary      Active announcement banners
// @Description  Enabled instance-wide announcement banners, shown at the top of every page (login included).
// @Tags         instance
// @Produce      json
// @Success      200  {object}  api.Response{data=[]store.AnnouncementBanner}
// @Router       /instance/banners [get]
func (s *Server) handleListActiveBanners(w http.ResponseWriter, r *http.Request) {
	banners, err := s.queries.ListAnnouncementBanners(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load banners")
		return
	}
	active := make([]store.AnnouncementBanner, 0, len(banners))
	for _, banner := range banners {
		if banner.Enabled {
			active = append(active, banner)
		}
	}
	api.JSON(w, http.StatusOK, active)
}

// @Summary      Announcement banner settings
// @Description  Full banner list, enabled or not. Instance admins only.
// @Tags         instance
// @Produce      json
// @Success      200  {object}  api.Response{data=[]store.AnnouncementBanner}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/settings/banners [get]
func (s *Server) handleGetBannerSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return
	}
	banners, err := s.queries.ListAnnouncementBanners(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load banners")
		return
	}
	api.JSON(w, http.StatusOK, banners)
}

// @Summary      Update announcement banners
// @Description  Replaces the full banner list. Instance admins only.
// @Tags         instance
// @Accept       json
// @Produce      json
// @Param        request  body  []store.AnnouncementBanner  true  "Banner list"
// @Success      200  {object}  api.Response{data=[]store.AnnouncementBanner}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/settings/banners [put]
func (s *Server) handleUpdateBannerSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return
	}

	var banners []store.AnnouncementBanner
	if err := json.NewDecoder(r.Body).Decode(&banners); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(banners) > maxAnnouncementBanners {
		api.JSONError(w, http.StatusBadRequest, "too many banners")
		return
	}
	for i := range banners {
		banners[i].Message = strings.TrimSpace(banners[i].Message)
		if banners[i].Message == "" {
			api.JSONError(w, http.StatusBadRequest, "banner message is required")
			return
		}
		// Rune count, not bytes: the UI's maxlength counts characters.
		if utf8.RuneCountInString(banners[i].Message) > 500 {
			api.JSONError(w, http.StatusBadRequest, "banner message is too long (max 500 characters)")
			return
		}
		banners[i].BackgroundColor = strings.TrimSpace(banners[i].BackgroundColor)
		if banners[i].BackgroundColor == "" {
			banners[i].BackgroundColor = "#004852"
		}
		if !bannerColorPattern.MatchString(banners[i].BackgroundColor) {
			api.JSONError(w, http.StatusBadRequest, "banner background color must be #rrggbb")
			return
		}
		if strings.TrimSpace(banners[i].ID) == "" {
			banners[i].ID = uuid.NewString()
		}
	}

	if err := s.queries.SaveAnnouncementBanners(r.Context(), banners); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save banners")
		return
	}

	s.writeAuditLog(r, UserFromContext(r.Context()), uuid.NullUUID{}, auditEntry{
		Action:       "instance.banners.update",
		ResourceType: "instance_setting",
		ResourceID:   store.InstanceSettingAnnouncementBanners,
		Context:      map[string]any{"banner_count": len(banners)},
	})

	// Push the new active set to every connected client (cross-replica via the
	// Postgres bridge) so banners update live instead of on the next reload.
	if s.wsFanout != nil {
		active := make([]store.AnnouncementBanner, 0, len(banners))
		for _, banner := range banners {
			if banner.Enabled {
				active = append(active, banner)
			}
		}
		if payload, err := json.Marshal(active); err == nil {
			s.wsFanout.PublishBroadcast(r.Context(), ws.Message{Type: "banner.updated", Payload: payload})
		}
	}

	api.JSON(w, http.StatusOK, banners)
}
