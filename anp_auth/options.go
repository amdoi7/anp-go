package anp_auth

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/bytedance/sonic"
	"github.com/openanp/anp-go/crypto"
)

// AuthenticatorOption configures an Authenticator.
type AuthenticatorOption func(*Authenticator) error

// WithDIDMaterial configures the Authenticator with a DID document and private key directly.
// This is the preferred method when you already have the DID material loaded.
func WithDIDMaterial(doc *DIDWBADocument, privateKey *ecdsa.PrivateKey) AuthenticatorOption {
	return func(a *Authenticator) error {
		if doc == nil {
			return fmt.Errorf("DID document cannot be nil")
		}
		if privateKey == nil {
			return fmt.Errorf("private key cannot be nil")
		}
		a.didDocument = doc
		a.privateKey = privateKey
		return nil
	}
}

// WithDIDCfgPaths configures the Authenticator to load DID material from file paths.
// The files will be loaded lazily on first use.
func WithDIDCfgPaths(didDocPath, privateKeyPath string) AuthenticatorOption {
	return func(a *Authenticator) error {
		if didDocPath == "" {
			return fmt.Errorf("DID document path cannot be empty")
		}
		if privateKeyPath == "" {
			return fmt.Errorf("private key path cannot be empty")
		}

		// Store paths for lazy loading
		a.cfg.DIDDocumentPath = didDocPath
		a.cfg.PrivateKeyPath = privateKeyPath
		return nil
	}
}

// WithEagerLoading loads the DID material immediately instead of lazily.
// This is useful if you want to catch configuration errors at startup.
// Should be used in combination with WithDIDPaths.
func WithEagerLoading() AuthenticatorOption {
	return func(a *Authenticator) error {
		if a.cfg.DIDDocumentPath == "" || a.cfg.PrivateKeyPath == "" {
			return fmt.Errorf("DID paths must be set before eager loading")
		}

		// Load DID document
		docBytes, err := os.ReadFile(a.cfg.DIDDocumentPath)
		if err != nil {
			return fmt.Errorf("read DID document: %w", err)
		}

		var doc DIDWBADocument
		if err := sonic.Unmarshal(docBytes, &doc); err != nil {
			return fmt.Errorf("decode DID document: %w", err)
		}

		// Load private key
		keyBytes, err := os.ReadFile(a.cfg.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}

		key, err := crypto.PrivateKeyFromPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("decode private key: %w", err)
		}

		a.didDocument = &doc
		a.privateKey = key
		return nil
	}
}

// WithCacheSize sets the initial capacity for token and header caches.
// This can improve performance if you know you'll be accessing many domains.
func WithCacheSize(size int) AuthenticatorOption {
	return func(a *Authenticator) error {
		if size < 0 {
			return fmt.Errorf("cache size must be non-negative")
		}
		a.tokens = make(map[string]string, size)
		a.authHeaders = make(map[string]string, size)
		return nil
	}
}

// WithLogger sets a custom logger for the Authenticator.
// If not provided, a no-op logger is used by default.
func WithLogger(logger Logger) AuthenticatorOption {
	return func(a *Authenticator) error {
		if logger == nil {
			return fmt.Errorf("logger cannot be nil")
		}
		a.logger = logger
		return nil
	}
}

// NewAuthenticator creates a new Authenticator using the functional options pattern.
//
// Example usage:
//
//	// With direct material
//	auth, err := NewAuthenticator(
//	    WithDIDMaterial(doc, privateKey),
//	)
//
//	// With paths (lazy loading)
//	auth, err := NewAuthenticator(
//	    WithDIDCfgPaths("did.json", "key.pem"),
//	)
//
//	// With paths (eager loading)
//	auth, err := NewAuthenticator(
//	    WithDIDCfgPaths("did.json", "key.pem"),
//	    WithEagerLoading(),
//	)
func NewAuthenticator(opts ...AuthenticatorOption) (*Authenticator, error) {
	a := &Authenticator{
		tokens:      make(map[string]string),
		authHeaders: make(map[string]string),
		logger:      defaultLogger, // Use no-op logger by default
	}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}

	// Validate that we have either direct material or paths
	hasDirectMaterial := a.didDocument != nil && a.privateKey != nil
	hasPaths := a.cfg.DIDDocumentPath != "" && a.cfg.PrivateKeyPath != ""

	if !hasDirectMaterial && !hasPaths {
		return nil, fmt.Errorf("must provide either DID material (WithDIDMaterial) or paths (WithDIDCfgPaths)")
	}

	return a, nil
}
