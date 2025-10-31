package anp_auth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"anp/crypto"

	"github.com/bytedance/sonic"
)

// Authenticator lazily loads DID material and issues DID-WBA authentication headers.
type Authenticator struct {
	cfg Config

	didDocument *DIDWBADocument
	privateKey  *ecdsa.PrivateKey
	loadOnce    sync.Once
	loadErr     error

	tokens      map[string]string
	authHeaders map[string]string
	cacheMutex  sync.Mutex
}

// Config controls how an Authenticator is created.
type Config struct {
	DIDDocumentPath string
	PrivateKeyPath  string

	Document   *DIDWBADocument
	PrivateKey *ecdsa.PrivateKey
}

// NewAuthenticator constructs an Authenticator. When Document/PrivateKey are provided,
// they are used directly; otherwise DIDDocumentPath and PrivateKeyPath must be set.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.Document == nil || cfg.PrivateKey == nil {
		if cfg.DIDDocumentPath == "" || cfg.PrivateKeyPath == "" {
			return nil, errors.New("anp_auth: provide Document/PrivateKey or DIDDocumentPath/PrivateKeyPath")
		}
	}

	return &Authenticator{
		cfg:         cfg,
		didDocument: cfg.Document,
		privateKey:  cfg.PrivateKey,
		tokens:      make(map[string]string),
		authHeaders: make(map[string]string),
	}, nil
}

// GenerateHeader returns the DID-WBA Authorization header for the target URL.
func (a *Authenticator) GenerateHeader(target string) (map[string]string, error) {
	return a.header(target, false)
}

// GenerateHeaderForce refreshes the header even if a cached value exists.
func (a *Authenticator) GenerateHeaderForce(target string) (map[string]string, error) {
	return a.header(target, true)
}

func (a *Authenticator) header(target string, force bool) (map[string]string, error) {
	domain, err := getDomain(target)
	if err != nil {
		return nil, err
	}

	if !force {
		a.cacheMutex.Lock()
		if token, ok := a.tokens[domain]; ok {
			a.cacheMutex.Unlock()
			logger.Debug("using cached JWT", "domain", domain)
			return map[string]string{"Authorization": "Bearer " + token}, nil
		}
		if header, ok := a.authHeaders[domain]; ok {
			a.cacheMutex.Unlock()
			logger.Debug("using cached DIDWba header", "domain", domain)
			return map[string]string{"Authorization": header}, nil
		}
		a.cacheMutex.Unlock()
	}

	if err := a.ensureMaterial(); err != nil {
		return nil, fmt.Errorf("load authentication material: %w", err)
	}

	header, err := GenerateAuthHeader(a.privateKey, a.didDocument, domain)
	if err != nil {
		return nil, fmt.Errorf("generate header: %w", err)
	}

	headerString := header.String()
	a.cacheMutex.Lock()
	a.authHeaders[domain] = headerString
	a.cacheMutex.Unlock()

	return map[string]string{"Authorization": headerString}, nil
}

// GenerateJSON creates the DID-WBA JSON payload equivalent to the Authorization header.
func (a *Authenticator) GenerateJSON(target string) (*AuthJSON, error) {
	domain, err := getDomain(target)
	if err != nil {
		return nil, err
	}
	if err := a.ensureMaterial(); err != nil {
		return nil, fmt.Errorf("load authentication material: %w", err)
	}
	return GenerateAuthJSON(a.privateKey, a.didDocument, domain)
}

// UpdateFromResponse caches a bearer token returned by the server.
func (a *Authenticator) UpdateFromResponse(target string, header http.Header) {
	token := header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer ") {
		return
	}

	domain, err := getDomain(target)
	if err != nil {
		logger.Warn("update token: invalid domain", "url", target, "error", err)
		return
	}

	a.cacheMutex.Lock()
	a.tokens[domain] = strings.TrimPrefix(token, "Bearer ")
	a.cacheMutex.Unlock()
}

// ClearToken removes any cached token/header for the target.
func (a *Authenticator) ClearToken(target string) {
	domain, err := getDomain(target)
	if err != nil {
		logger.Warn("clear token: invalid domain", "url", target, "error", err)
		return
	}
	a.cacheMutex.Lock()
	delete(a.tokens, domain)
	delete(a.authHeaders, domain)
	a.cacheMutex.Unlock()
}

func (a *Authenticator) ensureMaterial() error {
	a.loadOnce.Do(func() {
		if a.didDocument != nil && a.privateKey != nil {
			return
		}

		docBytes, err := os.ReadFile(a.cfg.DIDDocumentPath)
		if err != nil {
			a.loadErr = fmt.Errorf("read DID document: %w", err)
			return
		}

		var doc DIDWBADocument
		if err := sonic.Unmarshal(docBytes, &doc); err != nil {
			a.loadErr = fmt.Errorf("decode DID document: %w", err)
			return
		}

		keyBytes, err := os.ReadFile(a.cfg.PrivateKeyPath)
		if err != nil {
			a.loadErr = fmt.Errorf("read private key: %w", err)
			return
		}
		key, err := crypto.PrivateKeyFromPEM(keyBytes)
		if err != nil {
			a.loadErr = fmt.Errorf("decode private key: %w", err)
			return
		}

		a.didDocument = &doc
		a.privateKey = key
	})
	return a.loadErr
}

func getDomain(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	return u.Host, nil
}
