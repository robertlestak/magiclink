package auth

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenService handles JWT token generation and validation
type TokenService struct {
	hmacSecret []byte           // Used for HS256
	jwksPath   string           // Path to JWKS file
	cookieName string           // Cookie name for token
	tokenParam string           // Query parameter name for token
	defaultTTL time.Duration    // Default token TTL
	signingAlg string           // Signing algorithm (HS256 or RS256)
	issuer     string           // Issuer claim for tokens
	keyManager *KeyManager      // Key manager for keys
	keyPaths   []string         // Explicit paths to the key files
}

// GetCookieName returns the cookie name for the token
func (s *TokenService) GetCookieName() string {
	return s.cookieName
}

// GetTokenParam returns the query parameter name for the token
func (s *TokenService) GetTokenParam() string {
	return s.tokenParam
}

// GetKeyManager returns the key manager (if using one)
func (s *TokenService) GetKeyManager() *KeyManager {
	return s.keyManager
}

// TokenClaims represents the JWT claims
type TokenClaims struct {
	Claims map[string]string `json:"claims,omitempty"`
	jwt.RegisteredClaims
}

// NewTokenServiceHS256 creates a new token service using HS256
func NewTokenServiceHS256(hmacSecret, cookieName, tokenParam, issuer string, defaultTTL time.Duration) (*TokenService, error) {
	if hmacSecret == "" {
		return nil, errors.New("HMAC secret is required")
	}

	return &TokenService{
		hmacSecret: []byte(hmacSecret),
		cookieName: cookieName,
		tokenParam: tokenParam,
		defaultTTL: defaultTTL,
		signingAlg: "HS256",
		issuer:     issuer,
	}, nil
}

// NewTokenServiceRS256 creates a new token service using RS256
func NewTokenServiceRS256(jwksPath string, keyPaths []string, cookieName, tokenParam, issuer string, defaultTTL time.Duration) (*TokenService, error) {
	var keyManager *KeyManager
	var err error

	// If jwksPath is not provided, we'll still initialize but skip exporting
	// This avoids creating unwanted files in the current directory during tests

	// Create key manager with explicit key paths - requires pre-existing keys
	// Note: We've removed customKID parameter since primary key will now be the first key in the paths array
	keyManager, err = NewKeyManager("", keyPaths...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}

	// Only export JWKS if a path is provided
	if jwksPath != "" {
		jwksDir := filepath.Dir(jwksPath)
		if err := os.MkdirAll(jwksDir, 0755); err != nil {
			log.Printf("Warning: failed to create JWKS directory: %v", err)
		}
		
		if err := keyManager.ExportJWKS(jwksPath); err != nil {
			log.Printf("Warning: failed to export JWKS: %v", err)
		}
	}

	return &TokenService{
		jwksPath:   jwksPath,
		cookieName: cookieName,
		tokenParam: tokenParam,
		defaultTTL: defaultTTL,
		signingAlg: "RS256",
		issuer:     issuer,
		keyManager: keyManager,
		keyPaths:   keyPaths,
	}, nil
}


// GenerateToken creates a new JWT token
func (s *TokenService) GenerateToken(subject string, ttl time.Duration, claims map[string]string) (string, error) {
	if ttl == 0 {
		ttl = s.defaultTTL
	}

	// Set up claims
	now := time.Now()
	expiresAt := now.Add(ttl)

	tokenClaims := TokenClaims{
		Claims: claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   subject,
			Issuer:    s.issuer,
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(s.getSigningMethod(), tokenClaims)

	// Sign the token
	var tokenString string
	var err error

	if s.signingAlg == "RS256" {
		// Use key manager - always use the primary key for signing
		primaryKey := s.keyManager.GetPrimaryKey()
		if primaryKey == nil {
			return "", errors.New("no primary key available for signing")
		}
		
		// Set the key ID from the primary key
		token.Header["kid"] = primaryKey.ID
		
		// Sign with the primary key
		tokenString, err = token.SignedString(primaryKey.PrivateKey)
	} else {
		// HS256 mode - use a consistent kid for HS256 tokens
		token.Header["kid"] = "hs256-key-1"
		tokenString, err = token.SignedString(s.hmacSecret)
	}

	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and checks path authorization through claims
func (s *TokenService) ValidateToken(tokenString, requestPath string) (bool, map[string]string, string, time.Time, error) {
	// Parse the token
	token, err := s.parseToken(tokenString)
	if err != nil {
		return false, nil, "", time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate token
	if !token.Valid {
		return false, nil, "", time.Time{}, errors.New("invalid token")
	}

	// Get claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return false, nil, "", time.Time{}, errors.New("invalid claims format")
	}

	// Get expiration time
	expTime := time.Time{}
	if claims.ExpiresAt != nil {
		expTime = claims.ExpiresAt.Time
	}

	// If no request path provided, just validate the token
	if requestPath == "" {
		return true, claims.Claims, "", expTime, nil
	}

	// Authorization is now completely claims-based
	// No path pattern checking is done here anymore
	return true, claims.Claims, "", expTime, nil
}

// GetJWKS returns the JWKS for public key validation by reading from the jwksPath file
func (s *TokenService) GetJWKS() ([]byte, error) {
	if s.signingAlg != "RS256" {
		return nil, errors.New("JWKS only available for RS256")
	}

	// If no jwksPath is provided, generate JWKS in memory
	if s.jwksPath == "" {
		return s.keyManager.GenerateJWKS()
	}

	// Make sure the JWKS file is up to date
	err := s.updateJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to update JWKS: %w", err)
	}

	// Read the JWKS file
	jwksBytes, err := os.ReadFile(s.jwksPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS file: %w", err)
	}

	return jwksBytes, nil
}

// updateJWKS generates and saves the JWKS file
func (s *TokenService) updateJWKS() error {
	// Only available for RS256
	if s.signingAlg != "RS256" {
		return errors.New("JWKS only available for RS256")
	}

	// Skip if no jwksPath is provided (testing mode)
	if s.jwksPath == "" {
		return nil
	}

	// Make sure the JWKS directory exists
	jwksDir := filepath.Dir(s.jwksPath)
	if err := os.MkdirAll(jwksDir, 0755); err != nil {
		return fmt.Errorf("failed to create JWKS directory: %w", err)
	}

	// Generate and export JWKS
	return s.keyManager.ExportJWKS(s.jwksPath)
}

// Helper function to check if path matches pattern (legacy method)
func pathMatches(requestPath, patternsStr string) bool {
	// Check if there are multiple patterns (comma-separated)
	if strings.Contains(patternsStr, ",") {
		patterns := strings.Split(patternsStr, ",")
		for _, pattern := range patterns {
			// Check each pattern
			if matchSinglePattern(requestPath, strings.TrimSpace(pattern)) {
				return true
			}
		}
		return false
	}

	// Single pattern
	return matchSinglePattern(requestPath, patternsStr)
}

// Helper function to check if path matches any pattern from an array
func pathMatchesAny(requestPath string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	for _, pattern := range patterns {
		if matchSinglePattern(requestPath, pattern) {
			return true
		}
	}

	return false
}

// Helper function to check if a path matches a single pattern
func matchSinglePattern(requestPath, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(requestPath, prefix+"/")
	}
	return requestPath == pattern
}

// getSigningMethod returns the appropriate signing method
func (s *TokenService) getSigningMethod() jwt.SigningMethod {
	if s.signingAlg == "RS256" {
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodHS256
}

// getKeyFunc returns the key function for simple HS256 token validation
// This is only used for HS256 tokens or when not using a KeyManager
func (s *TokenService) getKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.hmacSecret, nil
	}
}

// parseToken parses a JWT token string and returns the token
func (s *TokenService) parseToken(tokenString string) (*jwt.Token, error) {
	if s.signingAlg == "RS256" {
		// Try to parse without verification to extract the kid
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		token, _, err := parser.ParseUnverified(tokenString, &TokenClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to parse token header: %w", err)
		}

		// Extract kid from token header
		if kid, ok := token.Header["kid"].(string); ok && kid != "" {
			// Find key with matching kid
			key := s.keyManager.GetKey(kid)
			if key != nil {
				// Create a keyfunc that specifically uses this key
				keyFunc := func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return key.PublicKey, nil
				}
				
				// Parse with the specific key
				return jwt.ParseWithClaims(tokenString, &TokenClaims{}, keyFunc)
			}
		}
		
		// If no kid or key not found, fallback to trying all keys
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			
			// Try the specific key first if kid exists
			if kid, ok := token.Header["kid"].(string); ok && kid != "" {
				key := s.keyManager.GetKey(kid)
				if key != nil {
					return key.PublicKey, nil
				}
			}
			
			// Try all keys one by one
			var lastErr error
			for _, key := range s.keyManager.GetAllKeys() {
				if err := token.Method.Verify(token.Raw, token.Signature, key.PublicKey); err == nil {
					return key.PublicKey, nil
				} else {
					lastErr = err
				}
			}
			
			if lastErr != nil {
				return nil, fmt.Errorf("no key found to verify token: %w", lastErr)
			}
			
			// Fallback to primary key
			primaryKey := s.keyManager.GetPrimaryKey()
			if primaryKey != nil {
				return primaryKey.PublicKey, nil
			}
			
			return nil, errors.New("no suitable key found for token validation")
		}
		
		return jwt.ParseWithClaims(tokenString, &TokenClaims{}, keyFunc)
	} else {
		// HS256 token parsing
		return jwt.ParseWithClaims(tokenString, &TokenClaims{}, s.getKeyFunc())
	}
}