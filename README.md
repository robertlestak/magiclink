# MagicLink

A stateless, JWT-based authentication service designed for seamless integration with API gateways and Kubernetes.

## Overview

MagicLink is a Go microservice that generates and validates temporary access tokens for web applications and APIs. It enables:

- Time-limited access to specific URL paths
- Seamless integration with NGINX, Istio, and other gateways
- Stateless operation with no database dependencies
- Support for pre-generated signing keys
- User-friendly token generation via web dashboard

The service provides both a user-facing dashboard for manual token generation and robust APIs for automation and integration.

## Key Features

### Authentication Capabilities

- **Claims-Based Authorization**: Use JWT claims for fine-grained authorization
- **Flexible TTL**: Configure token expiration from minutes to days
- **Custom Subject**: Specify the JWT subject claim (identity of the token)
- **Custom Claims**: Include arbitrary key-value pairs in tokens
- **Multi-Algorithm Support**: Choose between HS256 (HMAC) and RS256 (RSA) signing

### Integration Options

- **NGINX Integration**: Complete auth_request integration with Lua support
- **Istio JWT Authentication**: Native integration with Istio's JWT validation
- **Standalone API**: RESTful endpoints for custom integrations

### Security Features

- **External Key Management**: Bring your own keys for true statelessness 
- **JWKS Endpoint**: Dynamic JSON Web Key Set for public key distribution
- **Cookie Management**: Secure cookie-based authentication
- **Clean URLs**: Automatic redirection to remove token query parameters

### User Experience

- **Web Dashboard**: User-friendly interface for token management
- **Stateless Architecture**: No database required for high scalability
- **Custom Claims**: Flexible claim management for application-specific needs

## Installation

### Docker

The simplest way to run MagicLink is using Docker:

```bash
# Using HMAC signing (HS256)
docker run -p 8080:8080 -e HMAC_SECRET=your-secure-secret magiclink

# Using RSA signing (RS256)
docker run -p 8080:8080 -v /path/to/keys/private.pem:/keys/private.pem \
  -e SIGNING_ALG=RS256 -e KEY_PATHS=/keys/private.pem magiclink

# Using RSA signing (RS256) with multiple key files
docker run -p 8080:8080 \
  -v /path/to/primary.pem:/keys/primary.pem \
  -v /path/to/backup.pem:/keys/backup.pem \
  -e SIGNING_ALG=RS256 -e KEY_PATHS=/keys/primary.pem,/keys/backup.pem magiclink
```

### Docker Compose

For a complete example with NGINX integration:

```bash
cd examples/nginx
docker-compose up -d
```

### Kubernetes with Istio

For JWT authentication in Kubernetes with Istio:

```bash
kubectl apply -f examples/istio-jwt/
```

## Key Management

MagicLink uses a stateless approach to key management:

1. **For HS256**: Provide an HMAC secret via the `--hmac-secret` flag or `HMAC_SECRET` environment variable
2. **For RS256**: Provide explicit paths to pre-generated RSA private key files specified by `--key-paths` flag or `KEY_PATHS` environment variable (comma-separated)

### Key Preparation for RS256

When using RS256, you need to prepare RSA private keys in advance:

```bash
# Generate RSA key pairs (example using OpenSSL)
openssl genrsa -out /path/to/primary.private.pem 2048
openssl genrsa -out /path/to/backup.private.pem 2048
```

MagicLink works with RSA private key files in PEM format. The first key in the list of provided key paths is used as the primary signing key.

### Key ID Generation

Key IDs (kid) are generated deterministically from the public key components, ensuring:
- The same physical key will always have the same key ID across instances
- Key IDs are unique for each unique key
- Works with standardized key names like `tls.key` in Kubernetes environments
- Compatible with cert-manager and other certificate managers

MagicLink uses a cryptographic approach that hashes the public key components to generate a unique identifier independent of file paths or names. This is particularly useful in Kubernetes environments with cert-manager, where key files often have the same name (e.g., `tls.key`) in different directories.

You can derive the same key ID externally using this OpenSSL command:

```bash
openssl rsa -in your-key.pem -pubout | openssl dgst -sha256 -binary | head -c 8 | openssl base64 | tr '/+' '_-' | tr -d '='
```

This command:
1. Extracts the public key from your private key
2. Computes a SHA-256 hash of the entire public key
3. Takes the first 8 bytes of the hash
4. Base64url-encodes the result (with padding removed)

MagicLink will prefix this value with "kid" to form the complete key ID.

### Primary Key Selection

1. The first key in the list of provided key paths is always used as the primary signing key
2. The order of keys in the `--key-paths` parameter determines their priority
3. All instances with the same key paths in the same order will select the same primary key

This explicit approach provides more direct control over which key is used for signing while maintaining consistency across multiple instances without requiring coordination or state sharing.

## Configuration

MagicLink can be configured using either command-line flags or environment variables.

### Basic Authentication Settings

| Parameter | CLI Flag | Environment Variable | Description | Default |
|-----------|---------|---------------------|-------------|---------|
| HTTP Address | `--http-addr` | `HTTP_ADDR` | HTTP service address | `:8080` |
| Signing Algorithm | `--signing-alg` | `SIGNING_ALG` | `HS256` or `RS256` | `HS256` |
| HMAC Secret | `--hmac-secret` | `HMAC_SECRET` | Secret for HS256 signing | - |
| Default TTL | `--default-ttl` | `DEFAULT_TTL` | Default token lifetime | `15m` |
| Issuer | `--issuer` | `ISSUER` | JWT issuer claim | `magiclink` |
| Subject | - | - | JWT subject claim (in API request) | `user` |

### Integration Settings

| Parameter | CLI Flag | Environment Variable | Description | Default |
|-----------|---------|---------------------|-------------|---------|
| Cookie Name | `--cookie-name` | `COOKIE_NAME` | Name of auth cookie | `magic_token` |
| Token Parameter | `--token-param` | `TOKEN_PARAM` | Query parameter for token | `magic_token` |

### Key Management

| Parameter | CLI Flag | Environment Variable | Description | Default |
|-----------|---------|---------------------|-------------|---------|
| Key Paths | `--key-paths` | `KEY_PATHS` | Comma-separated list of file paths to RSA private keys | - |
| JWKS Path | `--jwks-path` | `JWKS_PATH` | Path to JWKS file (for RS256) | `./jwks.json` |

### System Settings

| Parameter | CLI Flag | Environment Variable | Description | Default |
|-----------|---------|---------------------|-------------|---------|
| Log Level | `--log-level` | `LOG_LEVEL` | Logging level | `info` |

## API Usage

### Generating a Token

```bash
curl -X POST http://localhost:8080/token -d '{
  "ttl": "1h",
  "sub": "admin",
  "claims": {
    "user_id": "123456",
    "custom_claim": "custom_value"
  }
}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Validating a Token

```bash
curl "http://localhost:8080/token/validate?magic_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Response:

```json
{
  "valid": true,
  "expires_in": "58m",
  "claims": {
    "user_id": "123456",
    "custom_claim": "custom_value"
  }
}
```

### Managing Keys (RS256)

List available keys:

```bash
curl "http://localhost:8080/keys"
```

Set a specific key as primary:

```bash
curl -X PUT "http://localhost:8080/keys/k1a2b3c4d5e6f7g8/primary"
```

## Integration Examples

### NGINX Integration

MagicLink integrates with NGINX using the `auth_request` directive and Lua scripting. See the full example in [examples/nginx](examples/nginx).

Key components:

```nginx
# Authentication request
location = /auth {
    internal;
    proxy_pass http://magiclink:8080/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}

# Protected location with auth_request
location /protected/ {
    auth_request /auth;
    error_page 401 = @unauthorized;
    
    # Handle token to cookie conversion
    auth_request_set $auth_token $upstream_http_x_auth_token;
    header_filter_by_lua_file /path/to/magiclink.lua;
}
```

### Istio JWT Integration

MagicLink integrates with Istio's native JWT validation. See the full example in [examples/istio-jwt](examples/istio-jwt).

Key components:

```yaml
# RequestAuthentication for JWT validation
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: magiclink-jwt
spec:
  selector:
    matchLabels:
      app: your-app
  jwtRules:
  - jwksUri: "http://magiclink.magiclink.svc.cluster.local:8080/.well-known/jwks.json"
    issuer: "magiclink"
    fromParams: ["magic_token"]
    fromCookies: ["magic_token"]

# AuthorizationPolicy for path-based access control
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: magiclink-jwt-policy
spec:
  selector:
    matchLabels:
      app: your-app
  action: ALLOW
  rules:
  - to:
    - operation:
        paths: ["/protected/*", "/api/private/*"]
    when:
    - key: request.auth.principal
      values: ["magiclink/admin", "magiclink/editor"]
```

## Advanced Features

### Multiple Key Support

MagicLink loads keys from multiple explicit file paths, which is useful for:

1. **Phased Key Rotation**: Specify the primary key first, followed by backup keys
2. **Kubernetes Multi-Mount**: Mount key files from different sources (ConfigMap, Secret)
3. **High Availability**: Include multiple keys to ensure availability

Example with multiple key files:
```
magiclink --signing-alg=RS256 --key-paths=/etc/certs/primary.pem,/etc/certs/backup.pem
```

All keys are loaded into a single key pool, with the first key used as the primary signing key. The JWKS file is stored at `./jwks.json` by default, but this location can be customized using the `--jwks-path` flag.

### Stateless Operation

MagicLink is designed for true statelessness:

1. **No Internal State**: The service maintains no internal state, making it ideal for horizontal scaling
2. **External Key Management**: Keys are provided externally rather than being generated internally
3. **Multiple Instance Support**: Multiple instances will behave identically when provided the same keys
4. **No Database Required**: All functionality operates without persistent storage

### Kubernetes Integration

MagicLink works well with Kubernetes patterns:

1. **Volume Mounts**: Mount key files from ConfigMaps or Secrets 
2. **Deterministic Key IDs**: Key IDs are derived from key content, not filenames
3. **Horizontal Scaling**: Stateless operation for multiple replicas
4. **Explicit Key Control**: Direct control over which key is used as primary

### Claims-Based Authorization

1. **Custom Claims**: Arbitrary key-value pairs in the token that your application can use for authorization decisions
2. **Subject Claim**: The main identity of the token, used by Istio and other integrations for authorization
3. **JWT Standard Claims**: Standard JWT claims like `exp` (expiration), `iat` (issued at), and `nbf` (not before) for enhanced security

### Custom Subject and Claims

You can specify the subject identity and include custom claims in tokens for additional context:

```json
{
  "sub": "editor-service",
  "claims": {
    "user_id": "12345",
    "user_email": "user@example.com",
    "role": "editor",
    "document_id": "doc-abc123"
  }
}
```

The subject identifies the entity to which the token was issued, and the claims are accessible in the validated token for additional authorization checks in your application or in integrations like Istio.

## Security Best Practices

### Deployment Architecture

For optimal security:

1. **Network Segregation**: Keep the admin interface internal, not internet-facing
2. **Service Separation**: Isolate the authentication service from application services
3. **TLS Encryption**: Always use HTTPS in production for all communications
4. **Proper TTLs**: Set appropriate token lifetimes based on security requirements

### Key Management

Securely manage cryptographic keys:

1. **Secure Storage**: Store HMAC secrets and private keys securely (e.g., Kubernetes Secrets)
2. **External Key Generation**: Generate keys externally using trusted tools (OpenSSL, CertManager, etc.)
3. **Key Isolation**: Keep private keys restricted to the authentication service only
4. **External Key Management**: Consider using external key management services for production

### Cookie Security

When using cookies for token storage:

1. **HttpOnly Flag**: Prevent JavaScript access to authentication cookies
2. **Secure Flag**: Ensure cookies are only sent over HTTPS
3. **SameSite Policy**: Set appropriate SameSite policy (usually "Lax" or "Strict")
4. **Limited Scope**: Use path restrictions to limit cookie scope

## Examples

Complete working examples are provided in the repository:

- [NGINX Integration](examples/nginx): Docker Compose example with NGINX auth_request integration
- [Istio JWT Authentication](examples/istio-jwt): Kubernetes example with Istio JWT validation

## License

MIT