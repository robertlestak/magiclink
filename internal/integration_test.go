package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/robertlestak/magiclink/internal/api"
	"github.com/robertlestak/magiclink/internal/log"
)

func init() {
	// Initialize logger with test level
	log.Init("error") // Use error level to reduce test output noise
}

// TestEndToEndFlow tests the complete flow from token generation to authorization
func TestEndToEndFlow(t *testing.T) {
	// Create a server with test config
	config := api.Config{
		HMACSecret: "test-integration-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := api.NewServer(config)
	router := server.Router()

	// Step 1: Generate a token
	tokenReq := api.TokenRequest{
		TTL:     "30m",
		Subject: "tester",
		Claims: map[string]string{
			"user_id": "12345",
			"email":   "test@example.com",
			"path":    "/protected/*",
		},
	}

	tokenReqBody, _ := json.Marshal(tokenReq)
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(tokenReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Failed to generate token, status: %d, body: %s", rr.Code, rr.Body.String())
	}

	var tokenResp api.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	if tokenResp.Token == "" {
		t.Fatal("Expected non-empty token")
	}

	token := tokenResp.Token
	t.Logf("Generated token: %s", token)

	// Magic links have been removed - no validation needed

	// Step 2: Validate the token
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/token/validate?token=%s", token), nil)
	rr = httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Failed to validate token, status: %d, body: %s", rr.Code, rr.Body.String())
	}

	var validateResp api.ValidationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &validateResp); err != nil {
		t.Fatalf("Failed to parse validation response: %v", err)
	}

	if !validateResp.Valid {
		t.Fatalf("Token validation failed: %s", validateResp.Error)
	}

	// Path patterns are now in claims
	if validateResp.Claims["path"] != "/protected/*" {
		t.Errorf("Expected claim 'path' to be '/protected/*', got '%v'", validateResp.Claims["path"])
	}

	if validateResp.Claims["user_id"] != "12345" || validateResp.Claims["email"] != "test@example.com" {
		t.Errorf("Claims mismatch: %v", validateResp.Claims)
	}

	// Step 3: Test authorization via query param
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth?token=%s", token), nil)
	req.URL.Path = "/protected/resource"
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Authorization failed via query param, status: %d, body: %s", rr.Code, rr.Body.String())
	}

	// Check x-auth-token header is set
	if rr.Header().Get("x-auth-token") == "" {
		t.Error("Expected x-auth-token header to be set for query param token")
	}

	// Step 4: Test authorization via cookie
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.URL.Path = "/protected/deep/path"
	req.AddCookie(&http.Cookie{
		Name:  "magic_token",
		Value: token,
	})
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Authorization failed via cookie, status: %d, body: %s", rr.Code, rr.Body.String())
	}

	// Check x-auth-token header is NOT set for cookie-based auth
	if rr.Header().Get("x-auth-token") != "" {
		t.Error("Expected x-auth-token header to NOT be set for cookie token")
	}

	// Step 5: With claims-based authorization, the path validation is now done by the application
	// So any path should be authorized with a valid token
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.URL.Path = "/unprotected/resource"
	req.AddCookie(&http.Cookie{
		Name:  "magic_token",
		Value: token,
	})
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected authorized for any path with valid token, got: %d", rr.Code)
	}

	// Step 6: Test with X-Original-URI header (NGINX style)
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-URI", fmt.Sprintf("/protected/nginx?token=%s", token))
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Authorization failed via X-Original-URI, status: %d, body: %s", rr.Code, rr.Body.String())
	}
}

// TestAuthorizationRequestEdgeCases tests edge cases for authorization requests
func TestAuthorizationRequestEdgeCases(t *testing.T) {
	// Create a server with test config
	config := api.Config{
		HMACSecret: "test-integration-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := api.NewServer(config)

	// Generate a token for testing with a short TTL
	tokenReq := api.TokenRequest{
		TTL:     "1s", // 1 second TTL
		Subject: "tester",
		Claims: map[string]string{
			"path": "/short/*",
		},
	}

	tokenReqBody, _ := json.Marshal(tokenReq)
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(tokenReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.CreateToken(rr, req)
	
	var tokenResp api.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}
	
	shortLivedToken := tokenResp.Token

	// Wait for the token to expire
	time.Sleep(2 * time.Second)

	// Test expired token
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.URL.Path = "/short/path"
	req.AddCookie(&http.Cookie{
		Name:  "magic_token",
		Value: shortLivedToken,
	})
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthorized for expired token, got: %d", rr.Code)
	}

	// Test with malformed token
	req = httptest.NewRequest(http.MethodGet, "/auth?token=malformed-token", nil)
	req.URL.Path = "/protected/resource"
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthorized for malformed token, got: %d", rr.Code)
	}

	// Test with Envoy-style path header
	// Generate a new token
	tokenReq = api.TokenRequest{
		Subject: "tester",
		Claims: map[string]string{
			"path": "/api/*",
		},
	}

	tokenReqBody, _ = json.Marshal(tokenReq)
	req = httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(tokenReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()

	server.CreateToken(rr, req)
	
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}
	
	envoyToken := tokenResp.Token

	// Test with Envoy style :path header
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set(":path", "/api/users")
	req.AddCookie(&http.Cookie{
		Name:  "magic_token",
		Value: envoyToken,
	})
	rr = httptest.NewRecorder()

	server.AuthorizeRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected OK for Envoy path header, got: %d", rr.Code)
	}
}