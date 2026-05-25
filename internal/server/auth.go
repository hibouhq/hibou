package server

import (
	"context"

	internalauth "github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/store"
)

func UserFromContext(ctx context.Context) *store.User {
	return internalauth.UserFromContext(ctx)
}
