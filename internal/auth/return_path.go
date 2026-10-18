package auth

import (
	"net/url"

	"github.com/hibouhq/hibou/internal/apitoken"
)

// SafeReturnPath is where a sign-in may send the browser back to, or "" for
// the default (home). Only the device approval page is allowed: its "sign in
// again" step must land back on the code being approved. The result is
// rebuilt from parsed parts, never echoed, so it cannot become an open
// redirect.
func SafeReturnPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Path != "/device" {
		return ""
	}
	code, ok := apitoken.NormalizeUserCode(u.Query().Get("user_code"))
	if !ok {
		return "/device"
	}
	return "/device?" + url.Values{"user_code": {apitoken.FormatUserCode(code)}}.Encode()
}
