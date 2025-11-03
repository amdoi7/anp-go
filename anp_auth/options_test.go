package anp_auth

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/openanp/anp-go/crypto"
)

func TestNewAuthenticator_DirectMaterial(t *testing.T) {
	// Create test DID document and key
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	auth, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
	)

	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	if auth == nil {
		t.Fatal("Expected authenticator to be created")
	}

	if auth.didDocument != doc {
		t.Error("DID document not set correctly")
	}

	if auth.privateKey != privateKey {
		t.Error("Private key not set correctly")
	}
}

func TestNewAuthenticator_NilMaterial(t *testing.T) {
	tests := []struct {
		name string
		doc  *DIDWBADocument
		key  *ecdsa.PrivateKey
	}{
		{
			name: "nil document",
			doc:  nil,
			key:  &ecdsa.PrivateKey{},
		},
		{
			name: "nil key",
			doc:  &DIDWBADocument{},
			key:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthenticator(
				WithDIDMaterial(tt.doc, tt.key),
			)
			if err == nil {
				t.Error("Expected error for nil material")
			}
		})
	}
}

func TestNewAuthenticator_Paths(t *testing.T) {
	// Create temporary files
	tmpDir := t.TempDir()

	// Create test DID document and key
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	// Save to files
	didPath := filepath.Join(tmpDir, "did.json")
	keyPath := filepath.Join(tmpDir, "key.pem")

	docBytes, _ := doc.Marshal()
	if err := os.WriteFile(didPath, docBytes, 0600); err != nil {
		t.Fatalf("Failed to write DID document: %v", err)
	}

	keyPEM, err := crypto.PrivateKeyToPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}

	// Test with paths (lazy loading)
	auth, err := NewAuthenticator(
		WithDIDCfgPaths(didPath, keyPath),
	)

	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	if auth.cfg.DIDDocumentPath != didPath {
		t.Error("DID document path not set correctly")
	}

	if auth.cfg.PrivateKeyPath != keyPath {
		t.Error("Private key path not set correctly")
	}

	// Material should not be loaded yet (lazy)
	if auth.didDocument != nil {
		t.Error("DID document should not be loaded yet (lazy loading)")
	}
}

func TestNewAuthenticator_EagerLoading(t *testing.T) {
	// Create temporary files
	tmpDir := t.TempDir()

	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	didPath := filepath.Join(tmpDir, "did.json")
	keyPath := filepath.Join(tmpDir, "key.pem")

	docBytes, _ := doc.Marshal()
	os.WriteFile(didPath, docBytes, 0600)

	keyPEM, _ := crypto.PrivateKeyToPEM(privateKey)
	os.WriteFile(keyPath, keyPEM, 0600)

	// Test with eager loading
	auth, err := NewAuthenticator(
		WithDIDCfgPaths(didPath, keyPath),
		WithEagerLoading(),
	)

	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	// Material should be loaded immediately
	if auth.didDocument == nil {
		t.Error("DID document should be loaded (eager loading)")
	}

	if auth.privateKey == nil {
		t.Error("Private key should be loaded (eager loading)")
	}
}

func TestNewAuthenticator_InvalidPaths(t *testing.T) {
	tests := []struct {
		name    string
		didPath string
		keyPath string
	}{
		{
			name:    "empty DID path",
			didPath: "",
			keyPath: "key.pem",
		},
		{
			name:    "empty key path",
			didPath: "did.json",
			keyPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthenticator(
				WithDIDCfgPaths(tt.didPath, tt.keyPath),
			)
			if err == nil {
				t.Error("Expected error for invalid paths")
			}
		})
	}
}

func TestNewAuthenticator_NoOptions(t *testing.T) {
	_, err := NewAuthenticator()
	if err == nil {
		t.Error("Expected error when no options provided")
	}
}

func TestNewAuthenticator_CacheSize(t *testing.T) {
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	auth, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
		WithCacheSize(100),
	)

	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	// Cache should have the specified capacity (can't directly test, but verify no error)
	if auth.tokens == nil || auth.authHeaders == nil {
		t.Error("Caches not initialized")
	}
}

func TestNewAuthenticator_InvalidCacheSize(t *testing.T) {
	doc, privateKey, _ := CreateDIDWBADocument("example.com", nil, nil, nil)

	_, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
		WithCacheSize(-1),
	)

	if err == nil {
		t.Error("Expected error for negative cache size")
	}
}

// Helper method to test if Marshal exists
func (d *DIDWBADocument) Marshal() ([]byte, error) {
	return sonic.Marshal(d)
}
