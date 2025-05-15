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
)

// TestLoadKeys tests the loadKeys method
func TestLoadKeys(t *testing.T) {
	// Create a temporary directory for keys
	tempDir := t.TempDir()

	// Create a KeyManager
	km, err := NewKeyManager("", tempDir)
	if err == nil {
		t.Fatalf("Expected error when creating key manager with empty directory")
	}

	// Generate a key first
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	
	keyPath := filepath.Join(tempDir, "rs256-test.private.pem")
	err = os.WriteFile(keyPath, privateKeyPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Now we should be able to create a key manager with the specific key path
	km, err = NewKeyManager("", keyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager with key: %v", err)
	}

	// We should have one key
	if len(km.Keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(km.Keys))
	}

	// Record the initial key ID
	initialKeyID := km.Keys[0].ID

	// Create a new instance with the same key path to test loading keys
	km2, err := NewKeyManager("", keyPath)
	if err != nil {
		t.Fatalf("Failed to create second key manager: %v", err)
	}

	// It should have loaded the same key
	if len(km2.Keys) != 1 {
		t.Fatalf("Expected 1 key after loading, got %d", len(km2.Keys))
	}

	if km2.Keys[0].ID != initialKeyID {
		t.Errorf("Expected loaded key ID to be %s, got %s", initialKeyID, km2.Keys[0].ID)
	}

	// Test loading key with non-standard file names
	// Test loading with directory with non-private key files
	textFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(textFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create directory inside keys dir
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Load keys again using the specific key path
	km3, err := NewKeyManager("", keyPath)
	if err != nil {
		t.Fatalf("Failed to create third key manager: %v", err)
	}

	if len(km3.Keys) != 1 {
		t.Fatalf("Expected 1 key after loading with extraneous files, got %d", len(km3.Keys))
	}
}

// TestStatelessKeyManagement tests the stateless key management approach
func TestStatelessKeyManagement(t *testing.T) {
	// Create a temporary directory for keys using t.TempDir() which is automatically cleaned up
	tempDir := t.TempDir()

	// Create two keys
	key1Path := filepath.Join(tempDir, "key1.private.pem")
	key2Path := filepath.Join(tempDir, "key2.private.pem")

	// Generate key 1
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

	// Generate key 2
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

	// Test 1: Key manager loads keys properly with explicit key paths
	km, err := NewKeyManager("", key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// Check that both keys were loaded
	if len(km.Keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(km.Keys))
	}

	// Get key IDs for comparison
	key1ID := deriveKeyIDFromKeyOpenSSL(privateKey1)
	key2ID := deriveKeyIDFromKeyOpenSSL(privateKey2)

	// Check primary key selection (should be deterministic based on sorted key IDs)
	primaryKey := km.GetPrimaryKey()
	if primaryKey == nil {
		t.Fatal("GetPrimaryKey returned nil")
	}

	expectedPrimaryID := key1ID
	if key2ID < key1ID {
		expectedPrimaryID = key2ID
	}

	if primaryKey.ID != expectedPrimaryID {
		t.Fatalf("Expected primary key to be %s (lexicographically first), got %s", 
			expectedPrimaryID, primaryKey.ID)
	}

	// Test 2: Key manager operates correctly with multiple instances
	// Create a second key manager with the same key paths
	km2, err := NewKeyManager("", key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create second key manager: %v", err)
	}

	// Check that both key managers return the same primary key
	primaryKey1 := km.GetPrimaryKey()
	primaryKey2 := km2.GetPrimaryKey()
	if primaryKey1.ID != primaryKey2.ID {
		t.Fatalf("Primary keys don't match between instances: %s vs %s", 
			primaryKey1.ID, primaryKey2.ID)
	}

	// Test 3: Export JWKS works on both instances
	jwks1, err := km.GenerateJWKS()
	if err != nil {
		t.Fatalf("Failed to generate JWKS from first instance: %v", err)
	}

	jwks2, err := km2.GenerateJWKS()
	if err != nil {
		t.Fatalf("Failed to generate JWKS from second instance: %v", err)
	}

	// Both should generate identical JWKS
	if string(jwks1) != string(jwks2) {
		t.Fatal("JWKS from two instances with identical keys are different")
	}

	// Test 4: Custom key ID selection works consistently across instances
	var nonDefaultKeyID string
	for _, key := range km.Keys {
		if key.ID != expectedPrimaryID {
			nonDefaultKeyID = key.ID
			break
		}
	}
	
	if nonDefaultKeyID == "" {
		t.Fatal("Could not find a non-default key")
	}
	
	// Create instances with custom key ID
	km3, err := NewKeyManager(nonDefaultKeyID, key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create custom key manager: %v", err)
	}
	
	km4, err := NewKeyManager(nonDefaultKeyID, key1Path, key2Path)
	if err != nil {
		t.Fatalf("Failed to create second custom key manager: %v", err)
	}

	// Both instances should use the specified custom key
	if km3.GetPrimaryKey().ID != nonDefaultKeyID {
		t.Fatalf("Custom key manager instance 1 using wrong key: expected %s, got %s", 
			nonDefaultKeyID, km3.GetPrimaryKey().ID)
	}
	
	if km4.GetPrimaryKey().ID != nonDefaultKeyID {
		t.Fatalf("Custom key manager instance 2 using wrong key: expected %s, got %s", 
			nonDefaultKeyID, km4.GetPrimaryKey().ID)
	}
	
	// Their JWKS should differ from the default key managers
	jwks3, err := km3.GenerateJWKS()
	if err != nil {
		t.Fatalf("Failed to generate JWKS from custom instance: %v", err)
	}
	
	// Parse JWKS to check if it contains the key IDs
	var jwksObj struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwks3, &jwksObj); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}
	
	if len(jwksObj.Keys) == 0 {
		t.Fatal("No keys found in JWKS")
	}
	
	// Verify the key IDs are in the JWKS
	foundCustomKey := false
	for _, key := range jwksObj.Keys {
		if kid, ok := key["kid"].(string); ok {
			if kid == nonDefaultKeyID {
				foundCustomKey = true
				break
			}
		}
	}
	
	if !foundCustomKey {
		t.Fatalf("Custom key ID %s not found in JWKS", nonDefaultKeyID)
	}
}