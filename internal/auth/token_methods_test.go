package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGetCookieName tests the GetCookieName method
func TestGetCookieName(t *testing.T) {
	cookieName := "test_cookie"
	tokenSvc, err := NewTokenServiceHS256("test-secret", cookieName, "token", "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	if got := tokenSvc.GetCookieName(); got != cookieName {
		t.Errorf("GetCookieName() = %v, want %v", got, cookieName)
	}
}

// TestGetTokenParam tests the GetTokenParam method
func TestGetTokenParam(t *testing.T) {
	tokenParam := "test_param"
	tokenSvc, err := NewTokenServiceHS256("test-secret", "cookie", tokenParam, "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	if got := tokenSvc.GetTokenParam(); got != tokenParam {
		t.Errorf("GetTokenParam() = %v, want %v", got, tokenParam)
	}
}

// TestGetKeyManager tests the GetKeyManager method
func TestGetKeyManager(t *testing.T) {
	// Create a temporary directory for keys
	tempDir := t.TempDir()

	// Generate a key in the temp directory
	keyPath := filepath.Join(tempDir, "key.private.pem")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = os.WriteFile(keyPath, privateKeyPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Test with RS256 token service
	tokenSvc, err := NewTokenServiceRS256(
		"", 
		[]string{keyPath}, // Use the actual file path we created
		"magic_token",
		"token",
		"test-issuer",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	// Get key manager
	keyManager := tokenSvc.GetKeyManager()
	if keyManager == nil {
		t.Fatal("Expected key manager to not be nil")
	}

	// Test with HS256 token service (should return nil)
	hs256TokenSvc, err := NewTokenServiceHS256("test-secret", "cookie", "token", "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create HS256 token service: %v", err)
	}

	if hs256TokenSvc.GetKeyManager() != nil {
		t.Error("Expected nil key manager for HS256 token service")
	}
}

// TestPathMatchesAdditional tests the pathMatches function with additional cases
func TestPathMatchesAdditional(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		pattern     string
		want        bool
	}{
		{"multiple patterns - first matches", "/foo", "/foo,/bar", true},
		{"multiple patterns - second matches", "/bar", "/foo,/bar", true},
		{"multiple patterns - none match", "/baz", "/foo,/bar", false},
		{"multiple patterns with spaces", "/bar", "/foo, /bar", true},
		{"multiple patterns with wildcards", "/foo/bar", "/api/*, /foo/*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathMatches(tt.requestPath, tt.pattern); got != tt.want {
				t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.requestPath, tt.pattern, got, tt.want)
			}
		})
	}
}