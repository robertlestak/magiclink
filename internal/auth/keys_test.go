package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestJWKSGeneration tests JWKS generation with prepared keys
func TestJWKSGeneration(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "jwks-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create two RSA keys
	key1Path := filepath.Join(tempDir, "key1.private.pem")
	key2Path := filepath.Join(tempDir, "key2.private.pem")

	// Generate first key
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

	// Generate second key
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

	// Create a key manager with explicit key paths
	km, err := NewKeyManager("", key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// Verify two keys were loaded
	if len(km.Keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(km.Keys))
	}

	// Create a temporary JWKS file
	jwksPath := filepath.Join(tempDir, "jwks.json")

	// Export JWKS to file
	err = km.ExportJWKS(jwksPath)
	if err != nil {
		t.Fatalf("Failed to export JWKS: %v", err)
	}

	// Read the JWKS file
	jwksData, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatalf("Failed to read JWKS file: %v", err)
	}

	// Parse JWKS JSON
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	// Should have two keys in JWKS
	if len(jwks.Keys) != 2 {
		t.Fatalf("Expected 2 keys in JWKS, got %d", len(jwks.Keys))
	}

	// Each key should have the required fields
	for i, key := range jwks.Keys {
		if key["kty"] != "RSA" {
			t.Fatalf("Key %d: Expected kty=RSA, got %v", i, key["kty"])
		}
		if key["use"] != "sig" {
			t.Fatalf("Key %d: Expected use=sig, got %v", i, key["use"])
		}
		if key["alg"] != "RS256" {
			t.Fatalf("Key %d: Expected alg=RS256, got %v", i, key["alg"])
		}
		if _, ok := key["kid"].(string); !ok {
			t.Fatalf("Key %d: Missing or invalid kid", i)
		}
		if _, ok := key["n"].(string); !ok {
			t.Fatalf("Key %d: Missing or invalid modulus (n)", i)
		}
		if _, ok := key["e"].(string); !ok {
			t.Fatalf("Key %d: Missing or invalid exponent (e)", i)
		}
	}
}

// TestCustomKeySelection tests the custom key selection functionality
func TestCustomKeySelection(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "primary-key-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create two RSA keys
	key1Path := filepath.Join(tempDir, "key1.private.pem")
	key2Path := filepath.Join(tempDir, "key2.private.pem")

	// Generate first key
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

	// Generate second key
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

	// Create a key manager without custom KID
	km, err := NewKeyManager("", key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// Verify two keys were loaded
	if len(km.Keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(km.Keys))
	}

	// Get the key IDs for later use
	key1ID := deriveKeyIDFromKeyOpenSSL(privateKey1)
	key2ID := deriveKeyIDFromKeyOpenSSL(privateKey2)

	// First key (by sorted ID) should be primary by default
	defaultPrimaryKey := km.GetPrimaryKey()
	if defaultPrimaryKey == nil {
		t.Fatal("GetPrimaryKey returned nil")
	}

	// Determine which key ID should be first alphabetically
	expectedDefaultID := key1ID
	if key2ID < key1ID {
		expectedDefaultID = key2ID
	}

	// Verify the default key selection
	if defaultPrimaryKey.ID != expectedDefaultID {
		t.Fatalf("Expected default primary key to be %s, got %s", expectedDefaultID, defaultPrimaryKey.ID)
	}

	// Get the non-default key ID
	nonDefaultID := key2ID
	if expectedDefaultID == key2ID {
		nonDefaultID = key1ID
	}

	// Create a new key manager with a custom KID
	km2, err := NewKeyManager(nonDefaultID, key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create key manager with custom KID: %v", err)
	}

	// Primary key should now be the specified non-default key
	customPrimaryKey := km2.GetPrimaryKey()
	if customPrimaryKey == nil {
		t.Fatal("GetPrimaryKey returned nil with custom KID")
	}
	if customPrimaryKey.ID != nonDefaultID {
		t.Fatalf("Expected primary key ID to be %s with custom KID, got %s",
			nonDefaultID, customPrimaryKey.ID)
	}

	// Test with invalid custom KID
	_, err = NewKeyManager("non-existent-key-id", key1Path, key2Path)
	if err == nil {
		t.Fatal("Expected error when using non-existent key ID")
	}
}

// TestKeyIDDerivationMethods tests both key ID derivation methods
func TestKeyIDDerivationMethods(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Get key IDs using both methods
	originalKeyID := deriveKeyIDFromKey(privateKey)
	opensslKeyID := deriveKeyIDFromKeyOpenSSL(privateKey)

	// Verify that the original method produces IDs with prefix "k"
	if !strings.HasPrefix(originalKeyID, "k") {
		t.Errorf("Original key ID doesn't have expected prefix 'k': %s", originalKeyID)
	}

	// Verify that the OpenSSL method produces IDs with prefix "kid"
	if !strings.HasPrefix(opensslKeyID, "kid") {
		t.Errorf("OpenSSL key ID doesn't have expected prefix 'kid': %s", opensslKeyID)
	}

	// Generate a different key
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate second RSA key: %v", err)
	}

	// Get key IDs for the second key
	originalKeyID2 := deriveKeyIDFromKey(privateKey2)
	opensslKeyID2 := deriveKeyIDFromKeyOpenSSL(privateKey2)

	// Verify different keys produce different IDs (both methods)
	if originalKeyID == originalKeyID2 {
		t.Error("Original method produced the same key ID for different keys")
	}
	if opensslKeyID == opensslKeyID2 {
		t.Error("OpenSSL method produced the same key ID for different keys")
	}

	// Generate multiple keys and verify uniqueness across a larger set
	const numKeys = 10
	originalKeyIDs := make(map[string]bool)
	opensslKeyIDs := make(map[string]bool)

	for i := 0; i < numKeys; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}

		origID := deriveKeyIDFromKey(key)
		opensslID := deriveKeyIDFromKeyOpenSSL(key)

		// Check for duplicate IDs
		if originalKeyIDs[origID] {
			t.Errorf("Duplicate original key ID detected: %s", origID)
		}
		if opensslKeyIDs[opensslID] {
			t.Errorf("Duplicate OpenSSL key ID detected: %s", opensslID)
		}

		originalKeyIDs[origID] = true
		opensslKeyIDs[opensslID] = true
	}
}

// TestDeterministicKeySelection tests that key selection is deterministic across instances
func TestDeterministicKeySelection(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "key-selection-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate and save multiple keys
	numKeys := 5
	privateKeys := make([]*rsa.PrivateKey, numKeys)
	keyIDs := make([]string, numKeys)

	for i := 0; i < numKeys; i++ {
		// Generate key
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key %d: %v", i, err)
		}
		privateKeys[i] = privateKey

		// Get the key ID
		keyIDs[i] = deriveKeyIDFromKeyOpenSSL(privateKey)

		// Encode and save the key
		keyPath := filepath.Join(tempDir, fmt.Sprintf("key%d.pem", i))
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
			t.Fatalf("Failed to write key file %d: %v", i, err)
		}
	}

	// Sort key IDs to determine which one should be selected by default
	sortedKeyIDs := make([]string, len(keyIDs))
	copy(sortedKeyIDs, keyIDs)
	sort.Strings(sortedKeyIDs)
	expectedPrimaryID := sortedKeyIDs[0]

	// Create multiple independent key managers and verify they select the same key
	// Collect all key paths
	keyPaths := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keyPaths[i] = filepath.Join(tempDir, fmt.Sprintf("key%d.pem", i))
	}

	for i := 0; i < 3; i++ {
		km, err := NewKeyManager("", keyPaths...)
		if err != nil {
			t.Fatalf("Failed to create key manager instance %d: %v", i, err)
		}

		// Verify all keys were loaded
		if len(km.Keys) != numKeys {
			t.Fatalf("Expected %d keys in instance %d, got %d", numKeys, i, len(km.Keys))
		}

		// Verify primary key is consistent
		primaryKey := km.GetPrimaryKey()
		if primaryKey == nil {
			t.Fatalf("GetPrimaryKey returned nil for instance %d", i)
		}

		if primaryKey.ID != expectedPrimaryID {
			t.Fatalf("Instance %d selected wrong primary key: expected %s, got %s",
				i, expectedPrimaryID, primaryKey.ID)
		}
	}

	// Test with a custom key ID
	customID := sortedKeyIDs[2] // Choose a key in the middle of the sorted list
	kmCustom, err := NewKeyManager(customID, keyPaths...)
	if err != nil {
		t.Fatalf("Failed to create key manager with custom ID: %v", err)
	}

	// Verify the custom key was selected
	primaryKey := kmCustom.GetPrimaryKey()
	if primaryKey == nil {
		t.Fatal("GetPrimaryKey returned nil for custom key")
	}

	if primaryKey.ID != customID {
		t.Fatalf("Expected primary key to be custom key %s, got %s",
			customID, primaryKey.ID)
	}

	// Verify behavior is consistent even after reloading keys
	if err := kmCustom.loadKeys(); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Primary key should still be the custom key after reload
	primaryKey = kmCustom.GetPrimaryKey()
	if primaryKey.ID != customID {
		t.Fatalf("After reload, expected primary key to remain %s, got %s",
			customID, primaryKey.ID)
	}
}

// TestExportJWKS tests exporting JWKS to a file
func TestExportJWKS(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "jwks-export-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create an RSA key
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

	// Create a key manager
	km, err := NewKeyManager("", keyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// Create JWKS output file path
	jwksPath := filepath.Join(tempDir, "jwks.json")

	// Export JWKS
	if err := km.ExportJWKS(jwksPath); err != nil {
		t.Fatalf("Failed to export JWKS: %v", err)
	}

	// Verify file exists
	fileInfo, err := os.Stat(jwksPath)
	if err != nil {
		t.Fatalf("Failed to stat JWKS file: %v", err)
	}
	if fileInfo.Size() == 0 {
		t.Fatal("JWKS file is empty")
	}

	// Read JWKS file
	jwksData, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatalf("Failed to read JWKS file: %v", err)
	}

	// Parse JWKS JSON
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	// Should have one key in JWKS
	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
}

// TestTokenServiceWithKeyManager tests the TokenService with a KeyManager
func TestTokenServiceWithKeyManager(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "token-service-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create an RSA key
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

	// Create a temporary JWKS file path
	jwksPath := filepath.Join(tempDir, "jwks.json")

	// Create a token service
	tokenSvc, err := NewTokenServiceRS256(
		jwksPath,
		[]string{keyPath}, // Use the key file we actually created
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

	// Generate a token
	ttl := 5 * time.Minute
	claims := map[string]string{"user": "testuser", "path": "/test/*"}

	token, err := tokenSvc.GenerateToken("user", ttl, claims)
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
	primaryKey := tokenSvc.keyManager.GetPrimaryKey()
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

	// Create a second key
	key2Path := filepath.Join(tempDir, "key2.private.pem")
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

	// Make key2 newer
	currentTime := time.Now()
	err = os.Chtimes(key2Path, currentTime, currentTime)
	if err != nil {
		t.Fatalf("Failed to update key file timestamp: %v", err)
	}

	// Reload token service to pick up the new key
	tokenSvc, err = NewTokenServiceRS256(
		jwksPath,
		[]string{keyPath, key2Path}, // Use the actual key paths we just created
		"magic_token",
		"token",
		"test-issuer",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to reload token service: %v", err)
	}

	// Generate a token with the second key (should now be primary as it's newer)
	token2, err := tokenSvc.GenerateToken("user", ttl, claims)
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	// Parse the second token
	parser2 := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken2, _, err := parser2.ParseUnverified(token2, &TokenClaims{})
	if err != nil {
		t.Fatalf("Failed to parse second token: %v", err)
	}

	// Just check that the second token has a kid
	kid2, ok := parsedToken2.Header["kid"].(string)
	if !ok {
		t.Fatal("Kid header not found or not a string in second token")
	}
	// With our new approach, the kid will be the same since we always use
	// the lexicographically first key ID

	// Validate both tokens (should still work)
	valid, _, _, _, err = tokenSvc.ValidateToken(token, "")
	if err != nil {
		t.Fatalf("Failed to validate first token after adding new key: %v", err)
	}
	if !valid {
		t.Fatal("Expected first token to still be valid")
	}

	valid, _, _, _, err = tokenSvc.ValidateToken(token2, "")
	if err != nil {
		t.Fatalf("Failed to validate second token: %v", err)
	}
	if !valid {
		t.Fatal("Expected second token to be valid")
	}

	// Get JWKS
	jwks, err := tokenSvc.GetJWKS()
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}

	// Parse JWKS JSON
	var jwksObj struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &jwksObj); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	// Should have two keys in JWKS
	if len(jwksObj.Keys) != 2 {
		t.Fatalf("Expected 2 keys in JWKS, got %d", len(jwksObj.Keys))
	}

	// JWKS should have entries for both kids
	foundKid1 := false
	foundKid2 := false
	for _, key := range jwksObj.Keys {
		if keyKid, ok := key["kid"].(string); ok {
			if keyKid == kid {
				foundKid1 = true
			}
			if keyKid == kid2 {
				foundKid2 = true
			}
		}
	}
	if !foundKid1 {
		t.Fatalf("Kid %s not found in JWKS", kid)
	}
	if !foundKid2 {
		t.Fatalf("Kid %s not found in JWKS", kid2)
	}
}
