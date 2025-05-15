# MagicLink with Istio JWT Authentication

This example demonstrates how to integrate MagicLink with Istio's native JWT authentication for securing Kubernetes services.

## Architecture Overview

This integration leverages Istio's advanced security features:

1. **MagicLink Service**: 
   - Generates and manages JWT tokens with RS256 signing
   - Provides a JWKS endpoint for key verification
   - Exposes an admin dashboard for token management
   - Implements key management with rotation support

2. **Istio JWT Authentication**:
   - Uses Istio's built-in JWT validation capabilities
   - Authenticates requests using standardized JWT protocols
   - Implements fine-grained path-based authorization

3. **Cookie Management**:
   - Custom EnvoyFilter for token-to-cookie conversion
   - Provides seamless user experience with clean URLs

## Components

### File Structure

| File | Purpose |
|------|---------|
| `00-cert-manager-issuer.yaml` | Sets up cert-manager Issuers for key generation |
| `01-cert-manager-certificates.yaml` | Creates Certificate resources for JWT signing |
| `01-namespaces.yaml` | Defines Kubernetes namespaces with Istio injection |
| `02-magiclink-service.yaml` | MagicLink service deployment and configuration |
| `03-demo-app.yaml` | Demo application with protected and public routes |
| `04-istio-jwt-auth.yaml` | JWT authentication and authorization policies |
| `05-token-cookie-filter.yaml` | EnvoyFilter for token-to-cookie conversion (simplified response-only implementation) |
| `06-istio-gateway.yaml` | Istio Gateway and VirtualServices for routing |
| `deploy.sh` | Script to deploy the complete demo |
| `cleanup.sh` | Script to remove all demo resources |

### Key Security Features

- **RS256 Signing**: Uses asymmetric cryptography for enhanced security
- **JWKS Integration**: Dynamic JSON Web Key Set (JWKS) endpoint for public key distribution
- **Path-Based Authorization**: Fine-grained access control for different API paths
- **Cookie-based Authentication**: Persistent authentication without exposing tokens in URLs

## Prerequisites

- Kubernetes cluster with Istio installed
- cert-manager installed in the cluster
- kubectl configured to access your cluster
- Docker for building the MagicLink image

## Getting Started

### 1. Deploy the Demo

```bash
# Make script executable
chmod +x deploy.sh

# Run the deployment script
./deploy.sh
```

The deployment script will:
1. Check prerequisites
2. Deploy cert-manager issuers and certificate resources for JWT signing
3. Build and deploy the MagicLink service
4. Deploy the demo application
5. Configure Istio JWT authentication
6. Set up the necessary routing

### 2. Configure Host Resolution

Add the following entries to your `/etc/hosts` file, replacing `<INGRESS_HOST>` with the IP address shown in the script output:

```
<INGRESS_HOST> demo-app.local demo-admin.local
```

### 3. Access the Demo

- **Public Page**: [http://demo-app.local/public/](http://demo-app.local/public/)
- **MagicLink Dashboard**: [http://demo-admin.local/dashboard](http://demo-admin.local/dashboard)
- **Protected Page**: [http://demo-app.local/protected/](http://demo-app.local/protected/) (requires authentication)

## Usage Guide

### Generating a Token

1. **Via Dashboard**:
   - Open [http://demo-admin.local/dashboard](http://demo-admin.local/dashboard)
   - Configure token TTL and subject
   - Add any custom claims needed for your application
   - Click "Generate Token" to create your authentication token

2. **Via API**:
   ```bash
   curl -X POST http://demo-admin.local/token \
     -H 'Content-Type: application/json' \
     -d '{
       "ttl": "1h",
       "sub": "user",
       "claims": {
         "user_id": "123456"
       }
     }'
   ```

### Authentication Flow

1. User opens the magic link containing a JWT token in the query parameter
2. Istio validates the token using MagicLink's JWKS endpoint
3. In the response phase, the EnvoyFilter extracts the token, sets a cookie, and redirects to a clean URL
4. Subsequent requests use the cookie for authentication
5. Istio's AuthorizationPolicy grants access to protected resources

## Troubleshooting

If authentication issues occur:

```bash
# Check MagicLink logs
kubectl -n magiclink logs -l app=magiclink

# Verify JWT validation configuration
kubectl -n demo-app get RequestAuthentication -o yaml

# Check authorization policies
kubectl -n demo-app get AuthorizationPolicy -o yaml

# Test JWKS endpoint
curl http://demo-admin.local/.well-known/jwks.json
```

## Clean Up

```bash
# Make script executable
chmod +x cleanup.sh

# Run the cleanup script
./cleanup.sh
```

## Implementation Details

### cert-manager Integration

MagicLink integrates with cert-manager for key management:
- cert-manager generates and manages RSA key pairs for JWT signing
- Multiple Certificate resources create distinct keys for signing and verification
- Keys are stored as Kubernetes secrets and mounted into the MagicLink pods
- Key rotation is handled automatically by cert-manager's renewal process
- Each certificate is used directly by its file path
- This ensures a simple and explicit approach to key handling

### JWT Authentication

Istio's RequestAuthentication is configured to:
- Validate tokens against MagicLink's JWKS endpoint
- Accept tokens from headers, cookies, and query parameters
- Verify the token issuer claim matches the MagicLink service

### Path-Based Authorization

AuthorizationPolicy resources control access:
- Protected paths (`/protected/*`, `/api/private/*`) require valid JWT
- Public paths (`/`, `/public/*`) are accessible without authentication

### Token-to-Cookie Conversion

A simplified custom EnvoyFilter written in Lua:
- Works only in the response phase
- Extracts tokens from query parameters
- Sets tokens as HttpOnly cookies
- Redirects to clean URLs without exposed tokens
- Compatible with Istio 1.8 and 1.9+