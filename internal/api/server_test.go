package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/robertlestak/magiclink/internal/log"
)

func init() {
	// Initialize logger with test level
	log.Init("error") // Use error level to reduce test output noise
}

func TestCreateToken(t *testing.T) {
	// Create a server with test config
	config := Config{
		HMACSecret: "test-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := NewServer(config)

	// Test cases
	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		validateResp   func(body []byte) error
	}{
		{
			name: "valid request",
			requestBody: map[string]interface{}{
				"ttl": "5m",
				"claims": map[string]string{
					"user": "testuser",
					"path": "/test/*",
				},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp TokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if resp.Token == "" {
					return fmt.Errorf("empty token")
				}
				return nil
			},
		},
		{
			name: "wildcard subdirectory",
			requestBody: map[string]interface{}{
				"claims": map[string]string{
					"path": "/foo/bar/*",
				},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp TokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if resp.Token == "" {
					return fmt.Errorf("empty token")
				}
				return nil
			},
		},
		{
			name: "non-wildcard path",
			requestBody: map[string]interface{}{
				"claims": map[string]string{
					"path": "/exact",
				},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp TokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				return nil
			},
		},
		{
			name: "invalid TTL",
			requestBody: map[string]interface{}{
				"ttl": "invalid",
				"claims": map[string]string{
					"path": "/test/*",
				},
			},
			expectedStatus: http.StatusBadRequest,
			validateResp:   nil,
		},
		{
			name: "custom claims",
			requestBody: map[string]interface{}{
				"claims": map[string]string{
					"user": "testuser",
					"role": "admin",
					"path": "/test/*",
				},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp TokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if resp.Token == "" {
					return fmt.Errorf("empty token")
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reqBody, err := json.Marshal(test.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			server.CreateToken(rr, req)

			if rr.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, rr.Code)
			}

			if test.validateResp != nil {
				if err := test.validateResp(rr.Body.Bytes()); err != nil {
					t.Errorf("Response validation failed: %v", err)
				}
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	// Create a server with test config
	config := Config{
		HMACSecret: "test-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := NewServer(config)

	// Generate a token for testing
	claims := map[string]string{
		"user": "testuser",
		"path": "/test/*",
	}
	token, err := server.tokenSvc.GenerateToken("user", 5*time.Minute, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Generate an expired token
	expiredToken, err := server.tokenSvc.GenerateToken("user", -1*time.Minute, claims)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Test cases
	tests := []struct {
		name           string
		token          string
		expectedStatus int
		validateResp   func(body []byte) error
	}{
		{
			name:           "valid token",
			token:          token,
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp ValidationResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if !resp.Valid {
					return fmt.Errorf("expected valid token")
				}
				if resp.Claims["user"] != "testuser" {
					return fmt.Errorf("expected claim 'user' to be 'testuser', got '%s'", resp.Claims["user"])
				}
				if resp.Claims["path"] != "/test/*" {
					return fmt.Errorf("expected claim 'path' to be '/test/*', got '%s'", resp.Claims["path"])
				}
				if resp.ExpiresIn == "" {
					return fmt.Errorf("expected non-empty expires_in")
				}
				return nil
			},
		},
		{
			name:           "expired token",
			token:          expiredToken,
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp ValidationResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if resp.Valid {
					return fmt.Errorf("expected invalid token")
				}
				if resp.Error == "" {
					return fmt.Errorf("expected error message")
				}
				return nil
			},
		},
		{
			name:           "invalid token",
			token:          "invalid-token",
			expectedStatus: http.StatusOK,
			validateResp: func(body []byte) error {
				var resp ValidationResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					return err
				}
				if resp.Valid {
					return fmt.Errorf("expected invalid token")
				}
				if resp.Error == "" {
					return fmt.Errorf("expected error message")
				}
				return nil
			},
		},
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusBadRequest,
			validateResp:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reqURL := "/token/validate"
			if test.token != "" {
				reqURL = fmt.Sprintf("/token/validate?token=%s", url.QueryEscape(test.token))
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			rr := httptest.NewRecorder()

			server.ValidateToken(rr, req)

			if rr.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, rr.Code)
			}

			if test.validateResp != nil {
				if err := test.validateResp(rr.Body.Bytes()); err != nil {
					t.Errorf("Response validation failed: %v", err)
				}
			}
		})
	}
}

func TestAuthorizeRequest(t *testing.T) {
	// Create a server with test config
	config := Config{
		HMACSecret: "test-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := NewServer(config)

	// Generate tokens for testing
	validClaims := map[string]string{
		"path": "/test/*",
	}
	validToken, err := server.tokenSvc.GenerateToken("user", 5*time.Minute, validClaims)
	if err != nil {
		t.Fatalf("Failed to generate valid token: %v", err)
	}

	exactPathClaims := map[string]string{
		"path": "/exact",
	}
	exactPathToken, err := server.tokenSvc.GenerateToken("user", 5*time.Minute, exactPathClaims)
	if err != nil {
		t.Fatalf("Failed to generate exact path token: %v", err)
	}

	// Test cases
	tests := []struct {
		name           string
		setupRequest   func(req *http.Request)
		expectedStatus int
		checkHeaders   func(headers http.Header) error
	}{
		{
			name: "token in query param",
			setupRequest: func(req *http.Request) {
				req.URL.RawQuery = fmt.Sprintf("token=%s", url.QueryEscape(validToken))
				req.URL.Path = "/test/foo"
			},
			expectedStatus: http.StatusOK,
			checkHeaders: func(headers http.Header) error {
				if headers.Get("x-auth-token") == "" {
					return fmt.Errorf("expected x-auth-token header")
				}
				return nil
			},
		},
		{
			name: "token in cookie",
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{
					Name:  "magic_token",
					Value: validToken,
				})
				req.URL.Path = "/test/foo"
			},
			expectedStatus: http.StatusOK,
			checkHeaders: func(headers http.Header) error {
				if headers.Get("x-auth-token") != "" {
					return fmt.Errorf("unexpected x-auth-token header")
				}
				return nil
			},
		},
		{
			name: "token in X-Original-URI",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Original-URI", fmt.Sprintf("/test/foo?token=%s", url.QueryEscape(validToken)))
				req.URL.Path = "/auth" // Different path in the request
			},
			expectedStatus: http.StatusOK,
			checkHeaders: func(headers http.Header) error {
				if headers.Get("x-auth-token") == "" {
					return fmt.Errorf("expected x-auth-token header")
				}
				return nil
			},
		},
		{
			name: "exact path match",
			setupRequest: func(req *http.Request) {
				req.URL.RawQuery = fmt.Sprintf("token=%s", url.QueryEscape(exactPathToken))
				req.URL.Path = "/exact"
			},
			expectedStatus: http.StatusOK,
			checkHeaders: func(headers http.Header) error {
				return nil
			},
		},
		{
			name: "no token",
			setupRequest: func(req *http.Request) {
				req.URL.Path = "/test/foo"
			},
			expectedStatus: http.StatusUnauthorized,
			checkHeaders:   nil,
		},
		{
			name: "Envoy path header",
			setupRequest: func(req *http.Request) {
				req.URL.RawQuery = fmt.Sprintf("token=%s", url.QueryEscape(validToken))
				req.Header.Set(":path", "/test/foo")
				req.URL.Path = "/auth" // Different path in the request
			},
			expectedStatus: http.StatusOK,
			checkHeaders: func(headers http.Header) error {
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			test.setupRequest(req)
			rr := httptest.NewRecorder()

			server.AuthorizeRequest(rr, req)

			if rr.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, rr.Code)
			}

			if test.checkHeaders != nil {
				if err := test.checkHeaders(rr.Header()); err != nil {
					t.Errorf("Header check failed: %v", err)
				}
			}
		})
	}
}

func TestGetJWKS(t *testing.T) {
	// Test HS256 configuration (should return 404)
	hs256Config := Config{
		HMACSecret: "test-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	hs256Server := NewServer(hs256Config)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	hs256Server.GetJWKS(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d for HS256, got %d", http.StatusNotFound, rr.Code)
	}

	// Cannot easily test RS256 configuration without generating/loading keys
	// In a real environment, this would involve setting up test keys
}

func TestRouter(t *testing.T) {
	// Create a server with test config
	config := Config{
		HMACSecret: "test-secret",
		CookieName: "magic_token",
		TokenParam: "token",
		DefaultTTL: 15 * time.Minute,
		SigningAlg: "HS256",
	}
	server := NewServer(config)

	// Get the router
	router := server.Router()

	// Test cases
	tests := []struct {
		name           string
		method         string
		path           string
		body           io.Reader
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "create token",
			method:         http.MethodPost,
			path:           "/token",
			body:           bytes.NewBufferString(`{"claims":{"path":"/test/*"}}`),
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "validate token invalid",
			method:         http.MethodGet,
			path:           "/token/validate?token=invalid",
			body:           nil,
			headers:        nil,
			expectedStatus: http.StatusOK, // Returns 200 with valid=false
		},
		{
			name:           "validate token missing",
			method:         http.MethodGet,
			path:           "/token/validate",
			body:           nil,
			headers:        nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "auth with no token",
			method:         http.MethodGet,
			path:           "/auth",
			body:           nil,
			headers:        nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "root redirect",
			method:         http.MethodGet,
			path:           "/",
			body:           nil,
			headers:        nil,
			expectedStatus: http.StatusFound, // 302 redirect
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, test.body)
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, rr.Code)
			}
		})
	}
}