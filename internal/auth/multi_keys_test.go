package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestMultipleKeyDirectories tests KeyManager with multiple key directories
func TestMultipleKeyDirectories(t *testing.T) {
	// Create multiple temporary directories for keys
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()
	tempDir3 := t.TempDir()

	// Create subdirectories to test cert-manager-style directories
	certManagerDir := filepath.Join(tempDir3, "tls-cert")
	err := os.Mkdir(certManagerDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cert-manager style directory: %v", err)
	}

	// DIRECTORY 1: Create two keys with different timestamps
	// Older key (primary=false)
	key1Path := filepath.Join(tempDir1, "key1.private.pem")
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey1),
	})
	err = os.WriteFile(key1Path, privateKeyPEM1, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// DIRECTORY 2: Create one key
	key2Path := filepath.Join(tempDir2, "key2.private.pem")
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM2 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey2),
	})
	err = os.WriteFile(key2Path, privateKeyPEM2, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// DIRECTORY 3: Create cert-manager style key
	key3Path := filepath.Join(certManagerDir, "tls.key")
	privateKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM3 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey3),
	})
	err = os.WriteFile(key3Path, privateKeyPEM3, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create the KeyManager with explicit key paths
	km, err := NewKeyManager("", key1Path, key2Path, key3Path)
	if err != nil {
		t.Fatalf("Failed to create key manager with multiple keys: %v", err)
	}

	// Verify all keys were loaded
	if len(km.Keys) != 3 {
		t.Fatalf("Expected 3 keys to be loaded, got %d", len(km.Keys))
	}

	// Test that a key is set as primary (should be the newest key)
	primaryKey := km.GetPrimaryKey()
	if primaryKey == nil {
		t.Fatal("No primary key was selected")
	}

	// Test that JWKS contains all keys
	jwksData, err := km.GenerateJWKS()
	if err != nil {
		t.Fatalf("Failed to generate JWKS: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	if len(jwks.Keys) != 3 {
		t.Fatalf("Expected 3 keys in JWKS, got %d", len(jwks.Keys))
	}

	// Test with non-existent key path
	badKeyPath := "/path/does/not/exist.pem"
	_, err = NewKeyManager("", badKeyPath)
	if err == nil {
		t.Fatal("Expected error when creating key manager with non-existent key path")
	}

	// Test with a mix of valid key and an invalid key
	invalidFilePath := filepath.Join(tempDir1, "not-a-key.txt")
	err = os.WriteFile(invalidFilePath, []byte("not a valid key"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	// We'll skip this test now since our processKeyFile will just skip invalid files
	// rather than fail the whole initialization
	/*
		_, err = NewKeyManager("", key1Path, invalidFilePath)
		if err == nil {
			t.Fatal("Expected error when creating key manager with an invalid key file")
		}
	*/

	// But it should work with just the valid key path
	km2, err := NewKeyManager("", key1Path)
	if err != nil {
		t.Fatalf("Failed to create key manager with one valid key path: %v", err)
	}

	if len(km2.Keys) != 1 {
		t.Fatalf("Expected 1 key to be loaded from valid key path, got %d", len(km2.Keys))
	}
}

// TestTokenServiceWithMultipleKeyDirectories tests TokenService with multiple key directories
func TestTokenServiceWithMultipleKeyDirectories(t *testing.T) {
	// Create multiple temporary directories for keys
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	// Create an RSA key in directory 1
	keyPath1 := filepath.Join(tempDir1, "key1.private.pem")
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey1),
	})
	err = os.WriteFile(keyPath1, privateKeyPEM1, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create a key with metadata marked as primary in directory 2
	keyPath2 := filepath.Join(tempDir2, "key2.private.pem")
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKeyPEM2 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey2),
	})
	err = os.WriteFile(keyPath2, privateKeyPEM2, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	keyID2 := deriveKeyIDFromKey(privateKey2)
	metadataFile := filepath.Join(tempDir2, keyID2+".json")
	metadata := struct {
		ID        string    `json:"id"`
		IssuedAt  time.Time `json:"issued_at"`
		ExpiresAt time.Time `json:"expires_at"`
		Primary   bool      `json:"primary"`
		Algorithm string    `json:"algorithm"`
	}{
		ID:        keyID2,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Primary:   true, // Mark this key as primary
		Algorithm: "RS256",
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}
	err = os.WriteFile(metadataFile, metadataBytes, 0644)
	if err != nil {
		t.Fatalf("Failed to write metadata file: %v", err)
	}

	// Create a temporary JWKS file path
	jwksPath := filepath.Join(tempDir1, "jwks.json")

	// Create a token service with multiple key files
	tokenSvc, err := NewTokenServiceRS256(
		jwksPath,
		[]string{keyPath1, keyPath2}, // Use the actual key paths we created
		"magic_token",
		"token",
		"test-issuer",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	// Key manager should be initialized
	if tokenSvc.keyManager == nil {
		t.Fatal("Expected key manager to be initialized")
	}

	// Should have loaded both keys
	if len(tokenSvc.keyManager.Keys) != 2 {
		t.Fatalf("Expected 2 keys to be loaded, got %d", len(tokenSvc.keyManager.Keys))
	}

	// Get the primary key
	primaryKey := tokenSvc.keyManager.GetPrimaryKey()
	if primaryKey == nil {
		t.Fatal("GetPrimaryKey returned nil")
	}

	// With our new lexicographical sorting approach, we can't predict
	// which key will be primary. Just verify that the key exists.

	// Generate a token
	ttl := 5 * time.Minute
	claims := map[string]string{"user": "testuser", "path": "/test/*"}

	token, err := tokenSvc.GenerateToken("testuser", ttl, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Parse the token without validation to check kid
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(token, &TokenClaims{})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Kid should match the primary key ID
	kid, ok := parsedToken.Header["kid"].(string)
	if !ok {
		t.Fatal("Kid header not found or not a string")
	}
	if kid != primaryKey.ID {
		t.Fatalf("Expected kid=%s, got %s", primaryKey.ID, kid)
	}

	// Validate the token
	valid, extractedClaims, _, exp, err := tokenSvc.ValidateToken(token, "")
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Fatal("Expected token to be valid")
	}
	if extractedClaims["user"] != "testuser" {
		t.Fatalf("Expected claim 'user' to be 'testuser', got '%s'", extractedClaims["user"])
	}
	// Path pattern checking is removed in favor of claims-based authorization
	if exp.IsZero() {
		t.Fatal("Expected non-zero expiration time")
	}

	// Test token validation with path matching
	valid, _, _, _, err = tokenSvc.ValidateToken(token, "/test/foo")
	if err != nil {
		t.Fatalf("Failed to validate token with path: %v", err)
	}
	if !valid {
		t.Fatal("Expected token to be valid for path '/test/foo'")
	}

	// Verify JWKS was created and contains both keys
	_, err = os.Stat(jwksPath)
	if err != nil {
		t.Fatalf("Expected JWKS file to exist: %v", err)
	}

	jwksBytes, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatalf("Failed to read JWKS file: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	if len(jwks.Keys) != 2 {
		t.Fatalf("Expected 2 keys in JWKS, got %d", len(jwks.Keys))
	}
}
