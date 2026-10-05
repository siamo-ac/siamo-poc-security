// Package middleware holds HTTP middleware for the demo API.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/siamosystems/siamo-poc-security/internal/auth"
)

// ClaimsKey is where the verified claims are stashed for handlers.
type ctxKey string

const ClaimsKey ctxKey = "jwt-claims"

func contextWithClaims(ctx context.Context, c auth.Claims) context.Context {
	return context.WithValue(ctx, ClaimsKey, c)
}

// ClaimsFrom extracts verified claims from the request context.
func ClaimsFrom(r *http.Request) (auth.Claims, bool) {
	c, ok := r.Context().Value(ClaimsKey).(auth.Claims)
	return c, ok
}

// RequireAuth is the "always verify, never trust" gate: every protected
// request must present a valid token, no sessions, no cookies, no
// IP-based exceptions. Fail closed: anything unclear -> 401.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			deny(w, "missing or malformed Authorization header")
			return
		}
		claims, err := auth.Verify(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			deny(w, "invalid token: "+err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithClaims(r.Context(), claims)))
	})
}

func deny(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "reason": reason})
}
