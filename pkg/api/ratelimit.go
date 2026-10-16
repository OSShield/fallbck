package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// enrollLimiter throttles the unauthenticated enrollment endpoint per client IP: a
// token is single-use and the agent retries slowly, so 1 request/s with a burst of
// 5 is generous for real agents and useless for guessing tokens. The client IP is
// what the trusted-proxies middleware resolved into RemoteAddr.
func enrollLimiter() func(http.Handler) http.Handler {
	var (
		mu       sync.Mutex
		limiters = map[string]*ipLimiter{}
	)
	// ponytail: single in-memory map, fine for one server process; move to a shared
	// store if the API is ever scaled out
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			mu.Lock()
			now := time.Now()
			for k, l := range limiters {
				if now.Sub(l.seen) > 10*time.Minute {
					delete(limiters, k)
				}
			}
			l, ok := limiters[ip]
			if !ok {
				l = &ipLimiter{Limiter: rate.NewLimiter(rate.Limit(1), 5)}
				limiters[ip] = l
			}
			l.seen = now
			allowed := l.Allow()
			mu.Unlock()
			if !allowed {
				http.Error(w, "too many enrollment attempts", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type ipLimiter struct {
	*rate.Limiter
	seen time.Time
}
