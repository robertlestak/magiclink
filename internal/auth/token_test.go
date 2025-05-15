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
)

// TestNewTokenServiceHS256 tests the creation of a new token service with HS256
func TestNewTokenServiceHS256(t *testing.T) {
	// Test with valid parameters
	tokenSvc, err := NewTokenServiceHS256("test-secret", "magic_token", "token", "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if tokenSvc == nil {
		t.Fatal("Expected token service, got nil")
	}

	// Test with empty HMAC secret
	_, err = NewTokenServiceHS256("", "magic_token", "token", "test-issuer", 15*time.Minute)
	if err == nil {
		t.Fatal("Expected error for empty HMAC secret, got nil")
	}
}

// TestGenerateToken tests token generation
func TestGenerateToken(t *testing.T) {
	tokenSvc, err := NewTokenServiceHS256("test-secret", "magic_token", "token", "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	// Test with basic parameters
	ttl := 5 * time.Minute
	claims := map[string]string{"user": "testuser"}

	token, err := tokenSvc.GenerateToken("user", ttl, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Parse token to verify claims
	parsedToken, err := tokenSvc.parseToken(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	tokenClaims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		t.Fatal("Failed to extract token claims")
	}
	if tokenClaims.Claims["user"] != "testuser" {
		t.Fatalf("Expected claim 'user' to be 'testuser', got '%s'", tokenClaims.Claims["user"])
	}

	// Test with zero TTL (should use default)
	token, err = tokenSvc.GenerateToken("user", 0, claims)
	if err != nil {
		t.Fatalf("Failed to generate token with zero TTL: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token with zero TTL")
	}

	// Test with nil claims
	token, err = tokenSvc.GenerateToken("user", ttl, nil)
	if err != nil {
		t.Fatalf("Failed to generate token with nil claims: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token with nil claims")
	}

	// Test with additional claims
	additionalClaims := map[string]string{
		"user": "testuser", 
		"role": "admin",
		"org_id": "12345",
	}
	
	multiClaimsToken, err := tokenSvc.GenerateToken("user", ttl, additionalClaims)
	if err != nil {
		t.Fatalf("Failed to generate token with multiple claims: %v", err)
	}

	// Parse to verify multiple claims
	multiClaimsParsedToken, err := tokenSvc.parseToken(multiClaimsToken)
	if err != nil {
		t.Fatalf("Failed to parse multi-claims token: %v", err)
	}
	multiTokenClaims, ok := multiClaimsParsedToken.Claims.(*TokenClaims)
	if !ok {
		t.Fatal("Failed to extract multi-claims token claims")
	}
	
	if multiTokenClaims.Claims["user"] != "testuser" {
		t.Fatalf("Expected claim 'user' to be 'testuser', got '%s'", multiTokenClaims.Claims["user"])
	}
	if multiTokenClaims.Claims["role"] != "admin" {
		t.Fatalf("Expected claim 'role' to be 'admin', got '%s'", multiTokenClaims.Claims["role"])
	}
	if multiTokenClaims.Claims["org_id"] != "12345" {
		t.Fatalf("Expected claim 'org_id' to be '12345', got '%s'", multiTokenClaims.Claims["org_id"])
	}
}

// TestValidateToken tests token validation
func TestValidateToken(t *testing.T) {
	tokenSvc, err := NewTokenServiceHS256("test-secret", "magic_token", "token", "test-issuer", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	// Generate a token
	ttl := 5 * time.Minute
	claims := map[string]string{"user": "testuser"}

	token, err := tokenSvc.GenerateToken("user", ttl, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Test validation
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
	if exp.IsZero() {
		t.Fatal("Expected non-zero expiration time")
	}

	// Verify issuer claim
	parsedToken, err := tokenSvc.parseToken(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	tokenClaims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		t.Fatal("Failed to extract token claims")
	}
	if tokenClaims.Issuer != "test-issuer" {
		t.Fatalf("Expected issuer to be 'test-issuer', got '%s'", tokenClaims.Issuer)
	}

	// Test validation with a path - should always be valid now with claims-based approach
	valid, _, _, _, err = tokenSvc.ValidateToken(token, "/test/foo")
	if err != nil {
		t.Fatalf("Failed to validate token with path: %v", err)
	}
	if !valid {
		t.Fatal("Expected token to be valid with path parameter")
	}

	// Test validation with invalid token
	valid, _, _, _, err = tokenSvc.ValidateToken("invalid-token", "")
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
	if valid {
		t.Fatal("Expected invalid token to be invalid")
	}

	// Generate an expired token
	expiredTokenSvc, _ := NewTokenServiceHS256("test-secret", "magic_token", "token", "test-issuer", 15*time.Minute)
	token, _ = expiredTokenSvc.GenerateToken("user", -1*time.Minute, claims) // Expired 1 minute ago

	// Test validation with expired token
	valid, _, _, _, err = tokenSvc.ValidateToken(token, "")
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
	if valid {
		t.Fatal("Expected expired token to be invalid")
	}
}

// TestIssuerClaim tests that the issuer claim is properly set in tokens
func TestIssuerClaim(t *testing.T) {
	// Create token service with custom issuer
	customIssuer := "custom-issuer-123"
	tokenSvc, err := NewTokenServiceHS256("test-secret", "magic_token", "token", customIssuer, 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token service: %v", err)
	}

	// Generate a token
	token, err := tokenSvc.GenerateToken("user", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Parse token to verify issuer
	parsedToken, err := tokenSvc.parseToken(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Check issuer claim
	claims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		t.Fatal("Failed to extract token claims")
	}

	if claims.Issuer != customIssuer {
		t.Fatalf("Expected issuer to be '%s', got '%s'", customIssuer, claims.Issuer)
	}

	// Verify kid in token header
	if kid, ok := parsedToken.Header["kid"].(string); !ok || kid == "" {
		t.Fatal("Expected kid in token header, but it was missing or empty")
	}

	// Create another token service with different issuer
	anotherIssuer := "another-issuer"
	anotherTokenSvc, _ := NewTokenServiceHS256("test-secret", "magic_token", "token", anotherIssuer, 15*time.Minute)
	anotherToken, _ := anotherTokenSvc.GenerateToken("user", 5*time.Minute, nil)

	// Verify different issuer
	anotherParsedToken, _ := anotherTokenSvc.parseToken(anotherToken)
	anotherClaims, _ := anotherParsedToken.Claims.(*TokenClaims)

	if anotherClaims.Issuer != anotherIssuer {
		t.Fatalf("Expected issuer to be '%s', got '%s'", anotherIssuer, anotherClaims.Issuer)
	}

	// Verify empty issuer
	emptyIssuerTokenSvc, _ := NewTokenServiceHS256("test-secret", "magic_token", "token", "", 15*time.Minute)
	emptyIssuerToken, _ := emptyIssuerTokenSvc.GenerateToken("user", 5*time.Minute, nil)

	emptyIssuerParsedToken, _ := emptyIssuerTokenSvc.parseToken(emptyIssuerToken)
	emptyIssuerClaims, _ := emptyIssuerParsedToken.Claims.(*TokenClaims)

	if emptyIssuerClaims.Issuer != "" {
		t.Fatalf("Expected empty issuer, got '%s'", emptyIssuerClaims.Issuer)
	}
}

// TestJWKS tests that JWKS is properly generated
func TestJWKS(t *testing.T) {
	// Create a temporary directory for keys
	tempDir, err := os.MkdirTemp("", "jwks-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

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

	// Create temporary JWKS file path
	jwksPath := filepath.Join(tempDir, "jwks.json")

	// Create RS256 token service with key manager
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

	// Generate token
	token, err := tokenSvc.GenerateToken("user", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Parse token to extract kid
	parsedToken, err := tokenSvc.parseToken(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	tokenKid, ok := parsedToken.Header["kid"].(string)
	if !ok || tokenKid == "" {
		t.Fatal("Expected kid in token header, but it was missing or empty")
	}

	// Get JWKS
	jwksBytes, err := tokenSvc.GetJWKS()
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}

	// Parse JWKS
	var jwks map[string]interface{}
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	// Verify JWKS structure
	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("Expected at least 1 key in JWKS, got %v", keys)
	}

	keyObj, ok := keys[0].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid key object in JWKS")
	}

	// Verify key kid matches token kid
	jwksKid, ok := keyObj["kid"].(string)
	if !ok || jwksKid == "" {
		t.Fatal("Expected kid in JWKS, but it was missing or empty")
	}

	// Find the matching key in JWKS
	matchFound := false
	for _, key := range keys {
		keyMap, ok := key.(map[string]interface{})
		if !ok {
			continue
		}
		if keyKid, ok := keyMap["kid"].(string); ok && keyKid == tokenKid {
			matchFound = true
			break
		}
	}

	if !matchFound {
		t.Fatalf("Expected to find kid %s in JWKS, but it was not found", tokenKid)
	}

	// Verify required fields in key object
	if keyObj["kty"] != "RSA" {
		t.Fatalf("Expected kty='RSA', got %v", keyObj["kty"])
	}

	if keyObj["alg"] != "RS256" {
		t.Fatalf("Expected alg='RS256', got %v", keyObj["alg"])
	}

	if keyObj["use"] != "sig" {
		t.Fatalf("Expected use='sig', got %v", keyObj["use"])
	}

	// n and e are required for RSA keys
	if _, ok := keyObj["n"].(string); !ok {
		t.Fatal("Missing or invalid modulus (n) in JWKS")
	}

	if _, ok := keyObj["e"].(string); !ok {
		t.Fatal("Missing or invalid exponent (e) in JWKS")
	}
}

// TestPathMatches tests the path matching logic
func TestPathMatches(t *testing.T) {
	tests := []struct {
		requestPath string
		pattern     string
		expectMatch bool
	}{
		{"/foo", "/foo", true},
		{"/foo/bar", "/foo", false},
		{"/foo/bar", "/foo/*", true},
		{"/foo/bar/baz", "/foo/*", true},
		{"/foobar", "/foo/*", false},
		{"/foo", "/foo/*", false}, // /foo/* doesn't match /foo exactly, needs a trailing /
		{"/other", "/foo", false},
		{"/other", "/foo/*", false},
		{"/foo/", "/foo", false},
		{"/foo/", "/foo/*", true},
	}

	for _, test := range tests {
		result := pathMatches(test.requestPath, test.pattern)
		if result != test.expectMatch {
			t.Errorf("pathMatches(%q, %q) = %v, expected %v", test.requestPath, test.pattern, result, test.expectMatch)
		}
	}
}

// TestPathMatchesAny tests matching a path against multiple patterns
func TestPathMatchesAny(t *testing.T) {
	tests := []struct {
		requestPath string
		patterns    []string
		expectMatch bool
	}{
		{"/foo", []string{"/foo"}, true},
		{"/foo", []string{"/bar", "/foo"}, true},
		{"/foo/bar", []string{"/foo/*"}, true},
		{"/foo/bar", []string{"/bar", "/other", "/foo/*"}, true},
		{"/foo", []string{"/foo/*"}, false}, // /foo/* doesn't match /foo exactly
		{"/other", []string{"/foo", "/bar"}, false},
		{"/other", []string{}, false}, // Empty patterns
	}

	for _, test := range tests {
		result := pathMatchesAny(test.requestPath, test.patterns)
		if result != test.expectMatch {
			t.Errorf("pathMatchesAny(%q, %v) = %v, expected %v", test.requestPath, test.patterns, result, test.expectMatch)
		}
	}
}
