package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/robertlestak/magiclink/internal/api"
	"github.com/robertlestak/magiclink/internal/log"
)

func main() {
	var (
		httpAddr       = flag.String("http-addr", ":8080", "HTTP service address")
		jwksPath       = flag.String("jwks-path", "./jwks.json", "Path to JWKS file (for RS256)")
		hmacSecret     = flag.String("hmac-secret", "", "HMAC secret (for HS256)")
		cookieName     = flag.String("cookie-name", "magic_token", "Cookie name for token")
		tokenParam     = flag.String("token-param", "magic_token", "Query parameter name for token")
		defaultTTL     = flag.Duration("default-ttl", 15*time.Minute, "Default token TTL")
		signingAlg     = flag.String("signing-alg", "HS256", "Signing algorithm: HS256 or RS256")
		issuer         = flag.String("issuer", "magiclink", "Issuer claim for generated tokens")
		keyPathsStr    = flag.String("key-paths", "", "Comma-separated list of file paths to RSA private keys (required for RS256)")
		logLevel       = flag.String("log-level", "info", "Log level: trace, debug, info, warn, error")
	)
	flag.Parse()

	// Check environment variables and override flags if present
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		*logLevel = envLogLevel
	}

	// Initialize logger
	log.Init(*logLevel)
	log.Debug("Initializing server")

	// Check for HMAC secret in environment
	if envHmacSecret := os.Getenv("HMAC_SECRET"); envHmacSecret != "" {
		log.Debug("Using HMAC secret from environment variable")
		*hmacSecret = envHmacSecret
	}

	// Check for other environment variables
	if envHttpAddr := os.Getenv("HTTP_ADDR"); envHttpAddr != "" {
		log.Debugf("Using HTTP address from environment: %s", envHttpAddr)
		*httpAddr = envHttpAddr
	}

	if envCookieName := os.Getenv("COOKIE_NAME"); envCookieName != "" {
		log.Debugf("Using cookie name from environment: %s", envCookieName)
		*cookieName = envCookieName
	}

	if envTokenParam := os.Getenv("TOKEN_PARAM"); envTokenParam != "" {
		log.Debugf("Using token parameter from environment: %s", envTokenParam)
		*tokenParam = envTokenParam
	}

	if envIssuer := os.Getenv("ISSUER"); envIssuer != "" {
		log.Debugf("Using issuer from environment: %s", envIssuer)
		*issuer = envIssuer
	}

	if envJwksPath := os.Getenv("JWKS_PATH"); envJwksPath != "" {
		log.Debugf("Using JWKS path from environment: %s", envJwksPath)
		*jwksPath = envJwksPath
	} else {
		log.Debugf("Using default JWKS path: %s", *jwksPath)
	}
	
	if envKeyPaths := os.Getenv("KEY_PATHS"); envKeyPaths != "" {
		log.Debugf("Using key paths from environment: %s", envKeyPaths)
		*keyPathsStr = envKeyPaths
	}

	if envTTL := os.Getenv("DEFAULT_TTL"); envTTL != "" {
		if ttl, err := time.ParseDuration(envTTL); err == nil {
			log.Debugf("Using default TTL from environment: %s", ttl)
			*defaultTTL = ttl
		} else {
			log.Warnf("Invalid DEFAULT_TTL in environment: %s", envTTL)
		}
	}

	if envSigningAlg := os.Getenv("SIGNING_ALG"); envSigningAlg != "" {
		if envSigningAlg == "HS256" || envSigningAlg == "RS256" {
			log.Debugf("Using signing algorithm from environment: %s", envSigningAlg)
			*signingAlg = envSigningAlg
		} else {
			log.Warnf("Invalid SIGNING_ALG in environment: %s", envSigningAlg)
		}
	}

	// Parse keyPathsStr into slice
	var keyPaths []string
	if *keyPathsStr != "" {
		// Split by comma and trim whitespace
		for _, path := range strings.Split(*keyPathsStr, ",") {
			trimmedPath := strings.TrimSpace(path)
			if trimmedPath != "" {
				keyPaths = append(keyPaths, trimmedPath)
			}
		}
		log.Debugf("Parsed key paths: %v", keyPaths)
	}

	// Validate required fields
	if *signingAlg == "RS256" && len(keyPaths) == 0 {
		log.Fatal("When using RS256, key-paths must be provided containing RSA private key files")
	}

	if *signingAlg == "HS256" && *hmacSecret == "" {
		log.Fatal("When using HS256, hmac-secret must be provided")
	}

	// Ensure jwks-path directory exists if provided
	if *jwksPath != "" {
		jwksDir := filepath.Dir(*jwksPath)
		if err := os.MkdirAll(jwksDir, 0755); err != nil {
			log.Warnf("Failed to create JWKS directory: %v", err)
		}
	}

	// Create server configuration
	config := api.Config{
		JWKSPath:    *jwksPath,
		HMACSecret:  *hmacSecret,
		CookieName:  *cookieName,
		TokenParam:  *tokenParam,
		DefaultTTL:  *defaultTTL,
		SigningAlg:  *signingAlg,
		Issuer:      *issuer,
		KeyPaths:    keyPaths,
	}

	// Set up API server
	server := api.NewServer(config)
	httpServer := &http.Server{
		Addr:    *httpAddr,
		Handler: server.Router(),
	}

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start HTTP server
	go func() {
		log.Infof("Starting HTTP server on %s", *httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-done
	log.Info("Server shutdown initiated")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Gracefully shut down HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Errorf("HTTP server shutdown failed: %v", err)
	} else {
		log.Debug("HTTP server shut down successfully")
	}

	log.Info("Servers exited gracefully")
}