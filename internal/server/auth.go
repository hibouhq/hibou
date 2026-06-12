package server

import (
	"context"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func UserFromContext(ctx context.Context) *store.User {
	return internalauth.UserFromContext(ctx)
}
