package workload

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeleteStrictJSONAndStatus(t *testing.T) {
	for _, tc := range []struct {
		name, content, body string
		valid               bool
	}{
		{"non-json", "text/html", "<html>success</html>", false},
		{"null", "application/json", "null", false},
		{"array", "application/json", "[]", false},
		{"trailing", "application/json", "{} {}", false},
		{"jsonp", "application/jsonp", "{}", false},
		{"failure", "application/json", `{"kind":"Status","status":"Failure","code":403,"message":"secret"}`, false},
		{"contradictory", "application/json", `{"kind":"Status","status":"Success","code":500}`, false},
		{"success", "application/json", `{"kind":"Status","status":"Success","code":200}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.content)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			f.client.base = s.URL
			f.client.http = s.Client()
			err := f.client.delete(context.Background(), "execution", "owned", "job-uid")
			if (err == nil) != tc.valid {
				t.Fatalf("delete outcome error=%v want valid=%v", err, tc.valid)
			}
		})
	}
}
