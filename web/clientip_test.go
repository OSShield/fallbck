package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

func TestClientIP(t *testing.T) {
	var got string
	h := ClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = middleware.GetClientIP(r.Context())
	}))
	for _, tc := range []struct{ name, remote, xff, want string }{
		{"direct peer ignores XFF", "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"trusted proxy forwards client", "10.0.0.5:1234", "198.51.100.7", "198.51.100.7"},
		{"spoofed entry left of real client", "10.0.0.5:1234", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		{"trusted hops skipped", "10.0.0.5:1234", "198.51.100.7, 10.0.0.9", "198.51.100.7"},
		{"trusted proxy without XFF", "10.0.0.5:1234", "", ""},
	} {
		got = ""
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
