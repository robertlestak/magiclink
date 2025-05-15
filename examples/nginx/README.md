# MagicLink with NGINX Integration

This example demonstrates how to integrate MagicLink with NGINX to protect web resources using a clean, secure architecture.

## Architecture Overview

This integration uses a layered security approach with proper separation of concerns:

1. **MagicLink Service**: 
   - Internal authentication service that generates and validates tokens
   - Exposes a user-friendly dashboard for token management
   - Provides authentication endpoints for NGINX

2. **NGINX with OpenResty**: 
   - Public-facing gateway with Lua scripting capabilities
   - Handles token validation and cookie management
   - Protects designated resources based on token validity

## Key Security Features

- **Network Segregation**: Administrative dashboard is not directly exposed to the public
- **Service Separation**: NGINX handles public traffic; MagicLink handles only authentication
- **Cookie Management**: Tokens are stored securely in cookies for persistent authentication 
- **Clean URLs**: Query parameters are automatically removed after authentication

## Components

### Docker Services

1. **magiclink**: Authentication service that runs on internal and admin ports
   - Admin dashboard on port 8080 (exposed only to localhost)
   - Authentication API accessible to NGINX

2. **nginx**: Public-facing gateway with authentication integration
   - Uses OpenResty for Lua scripting capabilities
   - Implements the `auth_request` directive for MagicLink validation
   - Handles cookie management and token validation

### Network Configuration

- **magiclink-internal**: Private network for secure service communication
- **public-network**: Network for external access to NGINX

## How It Works

1. When a user accesses a protected resource, NGINX sends an authentication request to MagicLink
2. MagicLink validates the token (from query parameter or cookie)
3. If valid, NGINX allows access to the protected resource
4. If a token is provided via query parameter, NGINX's Lua script:
   - Sets the token as a cookie
   - Redirects to a clean URL (without the token parameter)
5. Future requests use the cookie for authentication until it expires

## Resource Types

- **/public/**: Public resources that don't require authentication
- **/protected/**: Resources that require MagicLink authentication

## Usage Guide

### Starting the Demo

```bash
# From this directory
docker-compose up -d

# View logs
docker-compose logs -f
```

### Accessing the Demo

1. **Access Public Page**: 
   - Visit http://localhost/public/
   - This page is accessible without authentication

2. **Access Protected Content**:
   - Try to access http://localhost/protected/
   - You'll see an access denied message with a link to the admin service

3. **Generate a Magic Link**:
   - Open the MagicLink dashboard at http://localhost:8080/dashboard
   - Configure a token with the following settings:
     - Path pattern: `/protected/*`
     - Base URL: `http://localhost`
     - TTL: Default (15 minutes) or your preferred duration
   - Click "Generate Token" and copy the magic link

4. **Use the Magic Link**:
   - Paste the magic link in your browser
   - You'll be redirected to the protected content
   - NGINX sets the token as a cookie and redirects to a clean URL

5. **Verify Persistent Authentication**:
   - You can now access http://localhost/protected/ directly
   - Authentication persists until the token expires

## Implementation Details

### NGINX Configuration

The NGINX configuration employs several important features:

- **auth_request**: Delegates authentication to the MagicLink service
- **Lua scripting**: Manages token extraction, cookie setting, and URL cleaning
- **Proxying**: Forwards authentication requests to the MagicLink service
- **Error handling**: Provides friendly error responses for authentication failures

### MagicLink Configuration

The MagicLink service is configured with:

- **HMAC signing**: Uses a secret key for token signing (JWT HS256)
- **Debug logging**: Enables detailed logging for troubleshooting
- **Default TTL**: Sets token expiration time (15 minutes by default)

## Security Notes

This configuration demonstrates key security principles but should be adapted for production:

1. **Use HTTPS**: Always use TLS in production environments
2. **Secure Keys**: Implement proper secrets management for signing keys
3. **Cookie Security**: Enable secure cookie flags in production (HttpOnly, Secure, SameSite)
4. **Network Security**: Restrict admin interface access more strictly in production
5. **Token TTL**: Adjust token expiration times based on security requirements

## Clean Up

```bash
# Stop and remove containers, networks, and volumes
docker-compose down
```