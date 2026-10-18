package auth

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/forge"
)

func TestSafeReturnPath(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"/device":                           "/device",
		"/device?user_code=bcdf-ghjk":       "/device?user_code=BCDF-GHJK",
		"/device?user_code=BCDFGHJK&x=1":    "/device?user_code=BCDF-GHJK",
		"/device?user_code=..%2Forgs":       "/device",
		"":                                  "",
		"/":                                 "",
		"/orgs":                             "",
		"//evil.example/device":             "",
		"https://evil.example/device":       "",
		"/\\evil.example/device":            "",
		"/device/../orgs":                   "",
		"javascript:alert(1)":               "",
		"https://user@evil.example/device?": "",
	}
	for raw, want := range cases {
		if got := SafeReturnPath(raw); got != want {
			t.Errorf("SafeReturnPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The return path rides in the signed state cookie: the callback sends the
// browser back to it, and editing it breaks the signature.
func TestOAuthStateCarriesReturnPath(t *testing.T) {
	t.Parallel()

	mgr := New(Config{SessionSecret: testSessionSecret, BaseURL: "https://hibou.example.com", CookieSecure: true,
		Providers: map[string]forge.Provider{"github": &fakeLoginProvider{}}}, nil)
	begin := func(returnTo string) *http.Cookie {
		t.Helper()
		recorder := httptest.NewRecorder()
		target := "/api/v1/auth/login?provider=github&return=" + url.QueryEscape(returnTo)
		if err := mgr.BeginOAuthFlow(recorder, httptest.NewRequest(http.MethodGet, target, nil), "github"); err != nil {
			t.Fatalf("BeginOAuthFlow: %v", err)
		}
		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies = %+v, want one state cookie", cookies)
		}
		return cookies[0]
	}
	returnPathOf := func(c *http.Cookie) string {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback", nil)
		req.AddCookie(c)
		return mgr.oauthReturnPath(req)
	}

	if got := returnPathOf(begin("/device?user_code=BCDF-GHJK")); got != "/device?user_code=BCDF-GHJK" {
		t.Fatalf("return path = %q, want the device page", got)
	}
	if got := returnPathOf(begin("https://evil.example/")); got != "/" {
		t.Fatalf("outside return path = %q, want /", got)
	}

	cookie := begin("/device")
	parts := strings.Split(cookie.Value, "|")
	parts[4] = hex.EncodeToString([]byte("/orgs"))
	tampered := &http.Cookie{Name: cookie.Name, Value: strings.Join(parts, "|")}
	if _, err := mgr.parseOAuthState(tampered.Value); err == nil {
		t.Fatal("a tampered return path must fail the signature")
	}
	if got := returnPathOf(tampered); got != "/" {
		t.Fatalf("tampered return path = %q, want /", got)
	}
}
