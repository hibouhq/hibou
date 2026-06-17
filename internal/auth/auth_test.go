package auth

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/store"
)

func TestManagerInvokeLoginHooks(t *testing.T) {
	t.Parallel()

	manager := &Manager{}
	done := make(chan struct{}, 1)
	manager.AddLoginHook(func(context.Context, *store.User, string, *oauth2.Token) {
		panic("boom")
	})
	manager.AddLoginHook(func(context.Context, *store.User, string, *oauth2.Token) {
		done <- struct{}{}
	})

	manager.invokeLoginHooks(context.Background(), &store.User{}, "github", &oauth2.Token{AccessToken: "token"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for login hook execution")
	}
}
