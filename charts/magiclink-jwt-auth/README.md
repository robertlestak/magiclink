# MagicLink JWT Authentication Chart

This Helm chart deploys Istio JWT authentication resources for applications using MagicLink.

## Overview

This chart configures Istio to authenticate requests using JWT tokens issued by MagicLink. It creates:

1. **RequestAuthentication** - Configures JWT validation settings
2. **AuthorizationPolicy (protected)** - Controls access to protected paths that require JWT auth
3. **EnvoyFilter (optional)** - Handles token-to-cookie conversion

By default, all paths not explicitly protected remain publicly accessible.

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- Istio v1.6+
- MagicLink service deployed and accessible

## Installation

```bash
# Install the chart with default values
helm install my-jwt-auth ./charts/magiclink-jwt-auth

# Install with custom values
helm install my-jwt-auth ./charts/magiclink-jwt-auth -f values.yaml
```

## Configuration

The following table lists the configurable parameters of the MagicLink JWT Authentication chart.

### MagicLink Service Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `magiclinkService.url` | MagicLink service URL (can be internal or external) | `http://magiclink.magiclink:8080` |
| `magiclinkService.issuer` | JWT issuer claim | `magiclink` |
| `magiclinkService.cookieName` | Cookie name for token storage | `magic_token` |
| `magiclinkService.tokenParam` | Query parameter name for token | `magic_token` |

### Application Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `application.namespace` | Target namespace for JWT auth (must already exist) | `default` |
| `application.selector.app` | Application selector | `my-app` |
| `application.allowedSubjects` | Allowed JWT subjects | `["user", "admin"]` |

### Path Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `protectedPaths` | Paths requiring JWT authentication | `["/protected/*", "/api/private/*"]` |

### Cookie Handling

| Parameter | Description | Default |
| --- | --- | --- |
| `cookieHandling.enabled` | Enable EnvoyFilter for cookie handling | `false` |

## Examples

### Basic Configuration

```yaml
magiclinkService:
  url: "http://magiclink.magiclink:8080"  # Can be internal or external
  issuer: "magiclink"

application:
  namespace: "my-app"  # This namespace must already exist
  selector:
    app: "my-app"
  allowedSubjects:
    - "user"

# Only these paths will require JWT authentication
# All other paths are publicly accessible by default
protectedPaths:
  - "/admin/*"
  - "/api/private/*"
```

### With Cookie Handling

```yaml
magiclinkService:
  url: "http://magiclink.magiclink:8080"  # Can be internal or external
  issuer: "magiclink"
  cookieName: "auth_token"
  tokenParam: "auth_token"

application:
  namespace: "my-app"  # This namespace must already exist
  selector:
    app: "my-app"
  allowedSubjects:
    - "user"

# Only these paths will require JWT authentication
# All other paths are publicly accessible by default
protectedPaths:
  - "/dashboard/*"

cookieHandling:
  enabled: true
```

## Notes

1. This chart should be installed after deploying the MagicLink service.
2. **The target namespace MUST already exist** and should have Istio injection enabled.
3. Ensure the MagicLink service is correctly referenced (`magiclinkService.name` and `magiclinkService.port`).
4. The JWT issuer claim must match the issuer configured in the MagicLink service.
5. The application selector must match the labels of your application pods.
6. Cookie handling is optional and requires Istio EnvoyFilter support.
7. Make sure the allowed subjects match the subjects you use when generating tokens.