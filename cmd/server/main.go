// Command server runs the siamo-poc-security demo API over HTTPS:
//
//	POST /login          -> {"token": "..."}  (demo creds: admin / demo1234)
//	POST /oauth2/token   -> {"access_token": "..."}  (OAuth2 client_credentials
//	                        grant, demo client: svc-reporting / svc-secret-42)
//	GET  /public         -> open to everyone
//	GET  /protected      -> requires "Authorization: Bearer <token>"
//	POST /secrets/{name} -> encrypt + store a secret (protected)
//	GET  /secrets/{name} -> decrypt + return it    (protected)
//
// Env: JWT_SECRET, STORE_KEY (demo defaults if unset).
// Flags: -addr (default 127.0.0.1:8443), -data (secret-file dir).
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/siamosystems/siamo-poc-security/internal/auth"
	"github.com/siamosystems/siamo-poc-security/internal/cert"
	"github.com/siamosystems/siamo-poc-security/internal/middleware"
	"github.com/siamosystems/siamo-poc-security/internal/store"
)

const (
	demoUser = "admin"
	demoPass = "demo1234"

	// OAuth2 demo client for the client_credentials grant
	// (machine-to-machine, RFC 6749 section 4.4). Hardcoded on purpose:
	// this endpoint is a mock token issuer, not an identity system.
	demoClientID     = "svc-reporting"
	demoClientSecret = "svc-secret-42"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	dataDir := flag.String("data", "data", "directory for the encrypted secret file")
	flag.Parse()

	st := store.New(filepath.Join(*dataDir, "secrets.json"))

	mux := http.NewServeMux()

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		if in.User != demoUser || in.Password != demoPass {
			// Fixed demo creds, deliberately constant-time-ish to keep the
			// POC small: the honest story is "this is not authN for real",
			// it just gets us a token to demo authZ with.
			http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		tok, err := auth.Issue(in.User)
		if err != nil {
			http.Error(w, `{"error":"could not issue token"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"token": tok})
	})

	mux.HandleFunc("GET /public", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"message": "this route needs no token"})
	})

	// Mock OAuth2 token endpoint: the client_credentials grant (RFC 6749
	// section 4.4). No human, no password — the client authenticates with its
	// own id + secret and gets a JWT access token. The resource server
	// (/protected etc.) validates that token exactly like a /login token:
	// the OAuth2 idea is that *issuing* and *accepting* are separate jobs.
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "client_credentials" ||
			r.FormValue("client_id") != demoClientID ||
			r.FormValue("client_secret") != demoClientSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		tok, err := auth.Issue("client:" + demoClientID)
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": tok,
			"token_type":   "Bearer",
			"expires_in":   int64(auth.TTL / time.Second),
		})
	})

	protected := http.NewServeMux()
	protected.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.ClaimsFrom(r)
		writeJSON(w, map[string]any{
			"message": "hello, authenticated user",
			"sub":     claims.Subject,
			"exp":     claims.ExpiresAt,
		})
	})
	protected.HandleFunc("POST /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Value == "" {
			http.Error(w, `{"error":"JSON body with non-empty \"value\" required"}`, http.StatusBadRequest)
			return
		}
		if err := st.Put(r.PathValue("name"), in.Value); err != nil {
			http.Error(w, `{"error":"store failed"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "stored (encrypted at rest)"})
	})
	protected.HandleFunc("GET /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		v, err := st.Get(r.PathValue("name"))
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"value": v})
	})
	mux.Handle("/", middleware.RequireAuth(protected))

	c, err := cert.SelfSigned()
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	srv := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS for the demo: once HTTPS, always HTTPS.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			mux.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("serving HTTPS on https://%s (self-signed cert, generated at startup)", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
