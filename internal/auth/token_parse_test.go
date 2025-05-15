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

// TestParseToken tests the parseToken method with different token scenarios
func TestParseToken(t *testing.T) {
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

	// Create RS256 token service
	tokenSvcRS256, err := NewTokenServiceRS256(
		"",
		[]string{keyPath}, // Use the key file we actually created
		"magic_token",
		"token",
		"test-issuer",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create RS256 token service: %v", err)
	}

	// Create HS256 token service
	tokenSvcHS256, err := NewTokenServiceHS256(
		"test-secret",
		"magic_token",
		"token",
		"test-issuer",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create HS256 token service: %v", err)
	}

	// Generate RS256 token
	rs256Token, err := tokenSvcRS256.GenerateToken("user", 5*time.Minute, map[string]string{"user": "testuser"})
	if err != nil {
		t.Fatalf("Failed to generate RS256 token: %v", err)
	}

	// Generate HS256 token
	hs256Token, err := tokenSvcHS256.GenerateToken("user", 5*time.Minute, map[string]string{"user": "testuser"})
	if err != nil {
		t.Fatalf("Failed to generate HS256 token: %v", err)
	}

	// Test parsing RS256 token
	rs256Parsed, err := tokenSvcRS256.parseToken(rs256Token)
	if err != nil {
		t.Fatalf("Failed to parse RS256 token: %v", err)
	}
	if !rs256Parsed.Valid {
		t.Fatal("Expected RS256 token to be valid")
	}

	// Test parsing HS256 token
	hs256Parsed, err := tokenSvcHS256.parseToken(hs256Token)
	if err != nil {
		t.Fatalf("Failed to parse HS256 token: %v", err)
	}
	if !hs256Parsed.Valid {
		t.Fatal("Expected HS256 token to be valid")
	}

	// Test cross-parsing (should fail)
	_, err = tokenSvcRS256.parseToken(hs256Token)
	if err == nil {
		t.Fatal("Expected error when parsing HS256 token with RS256 service")
	}

	_, err = tokenSvcHS256.parseToken(rs256Token)
	if err == nil {
		t.Fatal("Expected error when parsing RS256 token with HS256 service")
	}

	// Test parsing invalid token
	_, err = tokenSvcRS256.parseToken("invalid.token.here")
	if err == nil {
		t.Fatal("Expected error when parsing invalid token")
	}

	// Test key manager access
	keyManager := tokenSvcRS256.GetKeyManager()
	if keyManager == nil {
		t.Fatal("Expected key manager to not be nil")
	}

	// Verify we can get the primary key
	primaryKey := keyManager.GetPrimaryKey()
	if primaryKey == nil {
		t.Fatal("Expected primary key to not be nil")
	}
}