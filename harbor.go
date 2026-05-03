// Package harbor provides API key validation middleware for Go HTTP servers.
// It integrates with Harbor (https://harbor-black.vercel.app) to handle
// authentication, billing, and rate limiting for your API.
package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultValidateURL = "https://harbor-black.vercel.app/api/validate"
	DefaultKeyHeader   = "X-Harbor-Key"
	Version            = "0.1.0"
)

// KeyInfo holds the validated API key metadata.
type KeyInfo struct {
	KeyID          string `json:"keyId"`
	ProjectID      string `json:"projectId"`
	Plan           string `json:"plan"`
	CallsThisMonth int    `json:"callsThisMonth"`
	Name           string `json:"name"`
	Country        string `json:"country,omitempty"`
}

type contextKey string

const harborContextKey contextKey = "harbor"

// Config holds options for the Harbor middleware.
type Config struct {
	ProjectID   string
	KeyHeader   string
	ValidateURL string
	Optional    bool
	FailOpen    bool
	Timeout     time.Duration
}

type validateResponse struct {
	Valid          bool   `json:"valid"`
	KeyID          string `json:"keyId"`
	ProjectID      string `json:"projectId"`
	Plan           string `json:"plan"`
	CallsThisMonth int    `json:"callsThisMonth"`
	Name           string `json:"name"`
	Country        string `json:"country"`
	Error          string `json:"error"`
}

// Validate checks an API key against Harbor and returns KeyInfo if valid.
func Validate(apiKey string, opts ...string) (*KeyInfo, error) {
	validateURL := DefaultValidateURL
	if len(opts) > 0 && opts[0] != "" {
		validateURL = opts[0]
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", validateURL+"?key="+apiKey, nil)
	if err != nil { return nil, err }
	req.Header.Set("User-Agent", "harbor-sdk-go/"+Version)
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	var result validateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return nil, err }
	if !result.Valid { return nil, fmt.Errorf("harbor: %s", result.Error) }
	return &KeyInfo{KeyID: result.KeyID, ProjectID: result.ProjectID, Plan: result.Plan,
		CallsThisMonth: result.CallsThisMonth, Name: result.Name, Country: result.Country}, nil
}

// FromContext retrieves KeyInfo from a request context.
func FromContext(ctx context.Context) *KeyInfo {
	info, _ := ctx.Value(harborContextKey).(*KeyInfo)
	return info
}

// Middleware returns an http.Handler middleware that validates Harbor API keys.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.KeyHeader == "" { cfg.KeyHeader = DefaultKeyHeader }
	if cfg.ValidateURL == "" { cfg.ValidateURL = DefaultValidateURL }
	if cfg.Timeout == 0 { cfg.Timeout = 5 * time.Second }
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get(cfg.KeyHeader)
			if apiKey == "" {
				if cfg.Optional { next.ServeHTTP(w, r); return }
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"error":"Missing API key"}`)
				return
			}
			info, err := Validate(apiKey, cfg.ValidateURL)
			if err != nil {
				if cfg.FailOpen { next.ServeHTTP(w, r); return }
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"error":"Invalid or revoked API key"}`)
				return
			}
			if cfg.ProjectID != "" && info.ProjectID != cfg.ProjectID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, `{"error":"API key does not belong to this project"}`)
				return
			}
			ctx := context.WithValue(r.Context(), harborContextKey, info)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
