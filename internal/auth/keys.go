package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyPair represents a signing key pair with metadata
type KeyPair struct {
	ID         string          // Key ID (kid)
	PrivateKey *rsa.PrivateKey // For signing
	PublicKey  *rsa.PublicKey  // For verification
	LoadedAt   time.Time       // When the key was loaded
	Algorithm  string          // Signing algorithm (RS256)
}

// KeyManager manages signing keys
type KeyManager struct {
	Keys      []*KeyPair   // All available key pairs
	KeyPaths  []string     // Explicit paths to key files
	CustomKID string       // If set, specifies a custom key ID to use as primary
	mutex     sync.RWMutex // For thread-safety
}

// NewKeyManager creates a new key manager with the given configuration
func NewKeyManager(customKID string, keyPaths ...string) (*KeyManager, error) {
	// Create key manager
	km := &KeyManager{
		Keys:      make([]*KeyPair, 0),
		KeyPaths:  keyPaths,
		CustomKID: customKID,
	}

	// Load existing keys from provided paths
	if len(keyPaths) > 0 {
		if err := km.loadKeys(); err != nil {
			return nil, fmt.Errorf("failed to load keys: %w", err)
		}
	}

	// If no keys were loaded, return an error - keys must be provided
	if len(km.Keys) == 0 {
		return nil, fmt.Errorf("no keys found at paths: %v", keyPaths)
	}

	// If a custom KID is specified, check if it exists
	if customKID != "" {
		found := false
		for _, key := range km.Keys {
			if key.ID == customKID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("specified key ID %s not found in available keys", customKID)
		}
	}

	return km, nil
}

// loadKeys loads all key pairs from all provided key paths
func (km *KeyManager) loadKeys() error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// Clear existing keys
	km.Keys = make([]*KeyPair, 0)

	// Skip if no key paths are set
	if len(km.KeyPaths) == 0 {
		return nil
	}

	// Process each key path directly
	for _, keyPath := range km.KeyPaths {
		if keyPath == "" {
			continue
		}

		// Get the filename for logging purposes
		filename := filepath.Base(keyPath)

		// Process the key file directly
		if err := km.processKeyFile(keyPath, filename); err != nil {
			log.Printf("Warning: failed to process key file %s: %v", keyPath, err)
			continue // Skip to next file rather than failing completely
		}
	}

	// Sort keys by ID lexicographically for deterministic ordering
	sort.Slice(km.Keys, func(i, j int) bool {
		return km.Keys[i].ID < km.Keys[j].ID
	})

	return nil
}

// processKeyFile loads a key file and adds it to the key manager
func (km *KeyManager) processKeyFile(keyPath, filename string) error {
	// Read private key file
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		// Skip files that aren't valid PEM RSA private keys
		return nil
	}

	// Generate key ID using the OpenSSL-compatible method
	keyID := deriveKeyIDFromKeyOpenSSL(privateKey)

	// Create key pair
	keyPair := &KeyPair{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		LoadedAt:   time.Now(),
		Algorithm:  "RS256",
	}

	km.Keys = append(km.Keys, keyPair)
	return nil
}

// No longer needed since we're using explicit file paths

// Derive a consistent key ID from the key itself
func deriveKeyIDFromKey(privateKey *rsa.PrivateKey) string {
	// Extract public key components
	n := privateKey.PublicKey.N.Bytes()
	e := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
	
	// Concatenate components
	combined := append(n, e...)
	
	// Generate SHA-256 hash
	hash := sha256.Sum256(combined)
	
	// Base64 encode first 12 bytes (results in ~16 character string)
	return "k" + base64.RawURLEncoding.EncodeToString(hash[:12])
}

// deriveKeyIDFromKeyOpenSSL generates a key ID using a method that can be
// replicated with a simple OpenSSL command. This is particularly useful for
// Kubernetes environments with cert-manager where key files often have the same name
// (e.g., tls.key) in different directories.
//
// To derive the same ID with OpenSSL, use:
//
//	openssl rsa -in key.pem -pubout | openssl dgst -sha256 -binary | head -c 8 | openssl base64 | tr '/+' '_-' | tr -d '='
//
// This method:
// 1. Extracts only the public key (for security)
// 2. Computes a SHA-256 hash of the full public key in PKIX format
// 3. Takes the first 8 bytes of the hash (for a reasonable identifier length)
// 4. Uses base64url encoding (RFC 4648) without padding
func deriveKeyIDFromKeyOpenSSL(privateKey *rsa.PrivateKey) string {
	// Marshal the public key to PKIX (ASN.1 DER) format
	// This is the same format OpenSSL uses for public keys
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		// Fall back to the original method if marshaling fails
		return deriveKeyIDFromKey(privateKey)
	}
	
	// Generate SHA-256 hash of the public key
	hash := sha256.Sum256(pubKeyDER)
	
	// Base64url encode first 8 bytes (results in ~11 character string)
	// The prefix "kid" makes it clear this is a Key ID
	return "kid" + base64.RawURLEncoding.EncodeToString(hash[:8])
}

// GetPrimaryKey returns the current primary key for signing
func (km *KeyManager) GetPrimaryKey() *KeyPair {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	
	// If we have no keys, return nil
	if len(km.Keys) == 0 {
		return nil
	}
	
	// If a custom key ID is specified, try to find that key
	if km.CustomKID != "" {
		for _, key := range km.Keys {
			if key.ID == km.CustomKID {
				return key
			}
		}
		// If the specified key wasn't found (which shouldn't happen as we check in NewKeyManager),
		// fall back to the default selection
		log.Printf("Warning: specified key ID %s not found, using default key selection", km.CustomKID)
	}
	
	// Always use the first key in the array as primary
	// This corresponds to the first key path provided when creating the KeyManager
	return km.Keys[0]
}

// GetKey returns a key by ID
func (km *KeyManager) GetKey(keyID string) *KeyPair {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	for _, key := range km.Keys {
		if key.ID == keyID {
			return key
		}
	}

	return nil
}

// GetAllKeys returns all active keys
func (km *KeyManager) GetAllKeys() []*KeyPair {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	// Return a copy of the keys slice
	keys := make([]*KeyPair, len(km.Keys))
	copy(keys, km.Keys)

	return keys
}


// GenerateJWKS generates a JWKS document for all active keys
func (km *KeyManager) GenerateJWKS() ([]byte, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	// Create JWKS structure
	jwks := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: make([]map[string]interface{}, 0, len(km.Keys)),
	}

	// Add all active keys to JWKS
	for _, key := range km.Keys {
		if key.PublicKey != nil {
			jwks.Keys = append(jwks.Keys, map[string]interface{}{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": key.ID,
				"n":   base64URLEncode(key.PublicKey.N.Bytes()),
				"e":   base64URLEncode(intToBytes(key.PublicKey.E)),
			})
		}
	}

	// Marshal to JSON
	return json.MarshalIndent(jwks, "", "  ")
}

// ExportJWKS exports the JWKS to a file
func (km *KeyManager) ExportJWKS(filePath string) error {
	// Generate JWKS
	jwksBytes, err := km.GenerateJWKS()
	if err != nil {
		return fmt.Errorf("failed to generate JWKS: %w", err)
	}

	// Write to file
	err = os.WriteFile(filePath, jwksBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JWKS file: %w", err)
	}

	return nil
}

// Helper functions for encoding

// base64URLEncode encodes binary data to base64url format
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// intToBytes converts an integer to bytes
func intToBytes(n int) []byte {
	return big.NewInt(int64(n)).Bytes()
}