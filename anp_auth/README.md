# anp_auth

Package `anp_auth` implements DID-WBA (Decentralized Identifier - Web-Based Authentication) for Go applications.

## What's New in v2.0

### ✨ Major Improvements

- **Functional Options Pattern**: Elegant, composable configuration API
- **Full Dependency Injection**: No global state, DI-framework friendly
- **Logger Interface**: Inject your own logger (slog, zap, logrus, etc.)
- **Performance Boost**: Singleflight optimization prevents thundering herd
- **Sentinel Errors**: Type-safe error handling with `errors.Is()`
- **Constants Package**: No more magic strings

### 🔧 Migration from v1

```go
// v1 (deprecated)
anp_auth.SetLogger(logger)
auth, _ := anp_auth.NewAuthenticator(anp_auth.Config{
    DIDDocumentPath: "did.json",
    PrivateKeyPath:  "key.pem",
})

// v2 (recommended)
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
    anp_auth.WithLogger(myLogger), // Optional
)
```

See [Logger Integration Guide](./LOGGER_GUIDE.md) for details.

---

## Features

- **Server-side authentication**: Verify DID-WBA signatures and issue JWT tokens
- **Client-side authentication**: Generate DID-WBA signatures automatically
- **HTTP middleware**: Easy integration with standard Go HTTP servers
- **Transport layer**: Automatic authentication for HTTP clients
- **Pluggable nonce validation**: Support for distributed nonce validators

## Installation

```bash
go get github.com/openanp/anp-go
```

## Quick Start

### Server-Side: Protect Your API

```go
package main

import (
    "net/http"
    "time"
    
    "github.com/openanp/anp-go/anp_auth"
)

func main() {
    // Create a nonce validator
    nonceValidator := anp_auth.NewMemoryNonceValidator(6 * time.Minute)
    
    // Create a verifier
    verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
        JWTPublicKeyPEM:       []byte(publicKey),
        JWTPrivateKeyPEM:      []byte(privateKey),
        NonceValidator:        nonceValidator,
        AccessTokenExpiration: 60 * time.Minute,
    })
    if err != nil {
        panic(err)
    }
    
    // Protected handler
    protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        did, _ := anp_auth.DIDFromContext(r.Context())
        w.Write([]byte("Hello, " + did))
    })
    
    // Apply middleware
    http.Handle("/api/", anp_auth.Middleware(verifier)(protected))
    http.ListenAndServe(":8080", nil)
}
```

### Client-Side: Make Authenticated Requests

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    
    "github.com/openanp/anp-go/anp_auth"
)

func main() {
    // Create authenticator using functional options
    auth, err := anp_auth.NewAuthenticator(
        anp_auth.WithDIDCfgPaths("did-doc.json", "private-key.pem"),
    )
    if err != nil {
        panic(err)
    }
    
    // Create authenticated client
    client := anp_auth.NewClient(auth)
    
    // Make requests - authentication is automatic!
    resp, err := client.Get("https://api.example.com/profile")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

## Architecture

### NonceValidator Interface

To prevent replay attacks, the `Verifier` requires a `NonceValidator` implementation:

```go
type NonceValidator interface {
    Validate(ctx context.Context, did, nonce string) (bool, error)
}
```

**Built-in Validators:**

- `MemoryNonceValidator`: In-memory storage (NOT safe for production in distributed systems)

**Production Setup:**

For production deployments, implement a distributed nonce validator using Redis, Memcached, or a database:

```go
type RedisNonceValidator struct {
    client *redis.Client
    expiration time.Duration
}

func (v *RedisNonceValidator) Validate(ctx context.Context, did, nonce string) (bool, error) {
    key := fmt.Sprintf("nonce:%s:%s", did, nonce)
    
    // Try to set the key (NX = only if not exists)
    ok, err := v.client.SetNX(ctx, key, "1", v.expiration).Result()
    if err != nil {
        return false, err
    }
    
    return ok, nil
}
```

## API Reference

### Server-Side

#### Middleware

```go
// Middleware returns an HTTP middleware for authentication
func Middleware(verifier *DidWbaVerifier) func(http.Handler) http.Handler
```

#### Helper Middlewares

```go
// RequireDID ensures the request has an authenticated DID
func RequireDID(next http.Handler) http.Handler

// RequireSpecificDID ensures the DID matches allowed values
func RequireSpecificDID(allowedDIDs ...string) func(http.Handler) http.Handler
```

#### Context Helpers

```go
// DIDFromContext extracts the authenticated DID
func DIDFromContext(ctx context.Context) (string, bool)

// AccessTokenFromContext extracts the access token
func AccessTokenFromContext(ctx context.Context) (string, bool)
```

#### Verifier Configuration

```go
type DidWbaVerifierConfig struct {
    JWTPrivateKey         any           // Private key for signing JWTs
    JWTPublicKey          any           // Public key for verifying JWTs
    JWTPrivateKeyPEM      []byte        // PEM-encoded private key
    JWTPublicKeyPEM       []byte        // PEM-encoded public key
    JWTAlgorithm          string        // Default: "RS256"
    AccessTokenExpiration time.Duration // Default: 60 minutes
    TimestampExpiration   time.Duration // Default: 5 minutes
    DIDCacheExpiration    time.Duration // Default: 15 minutes
    AllowedDomains        []string      // Restrict to specific domains
    NonceValidator        NonceValidator // Required
    ResolveDIDDocument    ResolveDIDDocumentFunc // Optional custom resolver
    Now                   func() time.Time // Optional time function
    HTTPClient            *http.Client  // Optional HTTP client
}
```

### Client-Side

#### Transport

```go
// NewClient creates an HTTP client with automatic authentication
func NewClient(authenticator *Authenticator) *http.Client

// NewClientWithTransport creates a client with custom base transport
func NewClientWithTransport(authenticator *Authenticator, base http.RoundTripper) *http.Client
```

#### Authenticator Configuration (Functional Options)

```go
// Recommended: Use functional options pattern
auth, err := anp_auth.NewAuthenticator(opts ...AuthenticatorOption)

// Available options:
WithDIDCfgPaths(didDocPath, privateKeyPath string)     // Load from file paths (lazy)
WithDIDMaterial(doc *DIDWBADocument, key *ecdsa.PrivateKey) // Direct material
WithEagerLoading()                                   // Load immediately (for startup validation)
WithCacheSize(size int)                              // Pre-size caches for performance
WithLogger(logger Logger)                            // Inject custom logger
```

**Examples:**

```go
// Basic usage
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
)

// With eager loading (validate at startup)
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
    anp_auth.WithEagerLoading(),
)

// With custom logger
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
    anp_auth.WithLogger(myLogger),
)

// All options combined
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDMaterial(doc, privateKey),
    anp_auth.WithCacheSize(100),
    anp_auth.WithLogger(myLogger),
)
```

## Examples

### Advanced Server Setup

```go
// Custom nonce validator using Redis
redisValidator := &RedisNonceValidator{
    client:     redisClient,
    expiration: 6 * time.Minute,
}

// Custom DID resolver
customResolver := func(ctx context.Context, did string) (*anp_auth.DIDWBADocument, error) {
    // Implement custom DID resolution logic
    return resolveDIDFromDatabase(did)
}

verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
    JWTPrivateKeyPEM:      privateKeyPEM,
    JWTPublicKeyPEM:       publicKeyPEM,
    NonceValidator:        redisValidator,
    ResolveDIDDocument:    customResolver,
    AllowedDomains:        []string{"example.com", "api.example.com"},
    AccessTokenExpiration: 30 * time.Minute,
})
```

### Role-Based Access Control

```go
// Admin-only endpoint
adminHandler := anp_auth.RequireSpecificDID(
    "did:wba:admin.example.com",
    "did:wba:superadmin.example.com",
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Admin panel"))
}))

http.Handle("/admin", anp_auth.Middleware(verifier)(adminHandler))
```

### Custom HTTP Client

```go
auth, _ := anp_auth.NewAuthenticator(config)

// Use custom transport for proxy, TLS, etc.
transport := &http.Transport{
    TLSClientConfig: tlsConfig,
    Proxy:           http.ProxyFromEnvironment,
}

client := anp_auth.NewClientWithTransport(auth, transport)
client.Timeout = 30 * time.Second
```

## Breaking Changes from v1

### Verifier

- **Required**: `NonceValidator` must be provided (no default)
- Changed: Duration fields now use `time.Duration` instead of minutes
  - `AccessTokenExpireMinutes` → `AccessTokenExpiration`
  - `NonceExpirationMinutes` → removed (handled by NonceValidator)
  - `TimestampExpirationMinutes` → `TimestampExpiration`
  - `DIDCacheExpireMinutes` → `DIDCacheExpiration`
- Changed: `ExternalNonceValidator` (func) → `NonceValidator` (interface)
- Changed: `ResolveDIDDocumentFunc` → `ResolveDIDDocument`
- Changed: `NowFunc` → `Now`

### Signature Algorithm

- **Breaking**: Removed double SHA-256 hashing
- Now uses standard single SHA-256 hash: `ECDSA(SHA256(payload))`
- Old clients/servers using double hashing are incompatible

### Error Messages

- All error messages now use lowercase (Go convention)
- Example: "Domain not allowed" → "domain not allowed"

## Migration Guide

### From v1 to v2

1. Update verifier creation:

```go
// Before (v1)
verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
    NonceExpirationMinutes: 6,
    AccessTokenExpireMinutes: 60,
})

// After (v2)
nonceValidator := anp_auth.NewMemoryNonceValidator(6 * time.Minute)
verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
    NonceValidator: nonceValidator,
    AccessTokenExpiration: 60 * time.Minute,
})
```

2. Implement a production nonce validator for distributed systems

3. Update all clients and servers to use the new single-hash signature algorithm

## Security Considerations

### Production Deployment

⚠️ **WARNING**: `MemoryNonceValidator` is NOT safe for production use in distributed systems. It only prevents replay attacks within a single process.

**For production:**

1. Use a distributed cache (Redis, Memcached)
2. Implement the `NonceValidator` interface
3. Set appropriate expiration times
4. Monitor for replay attack attempts

### Nonce Management

- Nonces should expire after a reasonable time (5-10 minutes)
- Store nonces with their DID to prevent cross-DID replay attacks
- Clean up expired nonces regularly to prevent memory leaks

### JWT Keys

- Keep private keys secure
- Use strong key sizes (RSA 2048+ or ECDSA P-256+)
- Rotate keys periodically
- Never expose private keys in logs or error messages

## Contributing

See [DEVELOPMENT_PLAN.md](../.prd/DEVELOPMENT_PLAN.md) for the architecture roadmap and [CODE_REVIEW.md](../../CODE_REVIEW.md) for coding standards.

## License

See the main repository LICENSE file.
