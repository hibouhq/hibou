package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/store"
)

type cliTokenResponse struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleCreateCLIToken creates an API key for CLI authentication.
func (s *Server) handleCreateCLIToken(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		api.JSONError(w, http.StatusForbidden, "CLI token creation requires browser session login, not API key")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	name := fmt.Sprintf("cli-%d", time.Now().Unix())
	expiresAt := time.Now().Add(90 * 24 * time.Hour)
	scopes := json.RawMessage(`[
		"all"
	]`)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	rawKey := "hibou_" + hex.EncodeToString(raw)
	apiKey, err := s.queries.CreateAPIKey(r.Context(), user.ID, name, store.HashAPIKey(rawKey), scopes, &expiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create CLI token")
		return
	}

	api.JSON(w, http.StatusOK, cliTokenResponse{
		Key:       rawKey,
		Name:      apiKey.Name,
		ExpiresAt: expiresAt,
	})
}
