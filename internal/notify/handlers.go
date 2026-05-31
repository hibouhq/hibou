package notify

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type unreadCountResponse struct {
	Count int64 `json:"count"`
}

type notificationResponse struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Link      string    `json:"link"`
	Severity  *string   `json:"severity,omitempty"`
	Status    string    `json:"status"`
	CreatedAt string    `json:"created_at"`
}

func (s *Service) HandleListNotifications(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	pagination := api.ParsePagination(r)
	items, err := s.store.ListNotificationsByUser(r.Context(), dbgen.ListNotificationsByUserParams{
		UserID: user.ID,
		Limit:  int32(pagination.PerPage), //nolint:gosec // G115: pagination is bounded by API parsing.
		Offset: int32(pagination.Offset),  //nolint:gosec // G115: pagination is bounded by API parsing.
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list notifications")
		return
	}

	total, err := s.store.CountNotificationsByUser(r.Context(), user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to count notifications")
		return
	}

	responses := make([]notificationResponse, len(items))
	for i, item := range items {
		responses[i] = toResponse(item)
	}

	api.JSONList(w, responses, pagination.Page, pagination.PerPage, int(total))
}

func (s *Service) HandleUnreadCount(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	count, err := s.store.CountUnreadNotifications(r.Context(), user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to count unread notifications")
		return
	}

	api.JSON(w, http.StatusOK, unreadCountResponse{Count: count})
}

func (s *Service) HandleMarkRead(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	notificationID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid notification id")
		return
	}

	if err := s.store.MarkNotificationRead(r.Context(), dbgen.MarkNotificationReadParams{ID: notificationID, UserID: user.ID}); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to mark notification as read")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) HandleMarkAllRead(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := s.store.MarkAllNotificationsRead(r.Context(), user.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to mark notifications as read")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func toResponse(item dbgen.Notification) notificationResponse {
	return notificationResponse{
		ID:        item.ID,
		UserID:    item.UserID,
		Type:      item.Type,
		Title:     item.Title,
		Body:      item.Body,
		Link:      item.Link,
		Severity:  severityPtr(item.Severity),
		Status:    item.Status,
		CreatedAt: item.CreatedAt.UTC().Format(http.TimeFormat),
	}
}

func severityPtr(value dbgen.NullSeverityLevel) *string {
	if !value.Valid {
		return nil
	}
	severity := string(value.SeverityLevel)
	return &severity
}

func jsonNotification(notification dbgen.Notification) (json.RawMessage, error) {
	payload, err := json.Marshal(toResponse(notification))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(payload), nil
}
