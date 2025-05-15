# MagicLink Helm Chart

This Helm chart deploys MagicLink, a stateless, JWT-based authentication service designed for seamless integration with API gateways and Kubernetes.

## Overview

This chart deploys only the core MagicLink service, which provides JWT token generation and validation. Application-specific JWT authentication resources (such as Istio RequestAuthentication and AuthorizationPolicy) should be deployed separately using your own configuration.

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- cert-manager v1.0.0+ (for RS256 signing)
- Istio v1.6+ (optional, for Istio integration)

## Installation

### Add the repository

```bash
helm repo add magiclink https://YOUR-REPO-URL
helm repo update
```

### Install the chart

```bash
# Basic installation
helm install magiclink magiclink/magiclink

# Installation with custom values
helm install magiclink magiclink/magiclink -f values.yaml

# Installation with specific options
helm install magiclink magiclink/magiclink --set config.signingAlg=HS256 --set config.hmacSecret=your-secret
```

## Configuration

The following table lists the configurable parameters of the MagicLink chart and their default values.

### Global Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `namespace.create` | Create a namespace | `true` |
| `namespace.name` | Name of the namespace | `magiclink` |

### Image Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `image.repository` | MagicLink image repository | `registry.shdw.tech/magiclink` |
| `image.tag` | MagicLink image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `Always` |
| `replicaCount` | Number of MagicLink replicas | `1` |

### Service Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `service.name` | Port name | `http` |

### Resource Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `256Mi` |

### MagicLink Configuration Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `config.signingAlg` | Token signing algorithm (RS256 or HS256) | `RS256` |
| `config.cookieName` | Cookie name for token storage | `magic_token` |
| `config.tokenParam` | Query parameter name for token | `magic_token` |
| `config.issuer` | JWT issuer claim | `magiclink` |
| `config.logLevel` | Logging level | `info` |
| `config.autoRotateKeys` | Enable automatic key rotation | `false` |
| `config.httpAddr` | Service listening address | `:8080` |
| `config.keyPaths` | Paths to the key files | `/keys/primary/tls.key,/keys/secondary/tls.key` |
| `config.hmacSecret` | HMAC secret (for HS256 mode) | `""` |
| `config.defaultTTL` | Default token TTL | `15m` |

### Certificate Management Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `certManager.enabled` | Enable cert-manager | `true` |
| `certManager.issuer.create` | Create a cert-manager issuer | `true` |
| `certManager.issuer.selfSigned` | Use self-signed issuer | `true` |
| `certManager.primaryCert.create` | Create primary JWT signing certificate | `true` |
| `certManager.primaryCert.secretName` | Primary certificate secret name | `magiclink-jwt-signer-primary` |
| `certManager.secondaryCert.create` | Create secondary JWT signing certificate | `true` |
| `certManager.secondaryCert.secretName` | Secondary certificate secret name | `magiclink-jwt-signer-secondary` |

## Examples

### Basic Installation with HS256 Signing

```yaml
config:
  signingAlg: "HS256"
  hmacSecret: "your-secure-secret"
  
certManager:
  enabled: false
```

### RS256 Signing with cert-manager

```yaml
config:
  signingAlg: "RS256"
  
certManager:
  enabled: true
  issuer:
    create: true
    selfSigned: true
  primaryCert:
    create: true
  secondaryCert:
    create: true
```

## Additional Notes

- When using RS256 signing, cert-manager is required to generate and manage the signing keys.
- For production use, consider implementing proper certificate management using a real CA instead of self-signed certificates.
- For Istio JWT authentication, see the examples directory in the MagicLink repository for configuration examples.
- Application-specific JWT authentication resources should be managed separately from this core service chart.