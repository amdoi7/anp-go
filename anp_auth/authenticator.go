package anp_auth

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/bytedance/sonic"
	"github.com/openanp/anp-go/crypto"
	"golang.org/x/sync/singleflight"
)

// Authenticator lazily loads DID material and issues DID-WBA authentication headers.
type Authenticator struct {
	cfg cfg // internal config for lazy loading

	didDocument *DIDWBADocument
	privateKey  *ecdsa.PrivateKey
	loadOnce    sync.Once
	loadErr     error

	tokens      map[string]string
	authHeaders map[string]string
	cacheMutex  sync.Mutex

	// sf prevents thundering herd when multiple goroutines request headers
	// for the same domain simultaneously
	sf singleflight.Group

	// logger is the injected logger instance
	logger Logger
}

// cfg holds internal configuration for lazy loading
type cfg struct {
	DIDDocumentPath string
	PrivateKeyPath  string
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
			a.logger.Debug("using cached JWT", "domain", domain)
			return map[string]string{AuthorizationHeader: BearerScheme + token}, nil
		}
		if header, ok := a.authHeaders[domain]; ok {
			a.cacheMutex.Unlock()
			a.logger.Debug("using cached DIDWba header", "domain", domain)
			return map[string]string{AuthorizationHeader: header}, nil
		}
		a.cacheMutex.Unlock()
	}

	// Use singleflight to prevent thundering herd when multiple goroutines
	// request the same domain simultaneously
	result, err, _ := a.sf.Do(domain, func() (interface{}, error) {
		// Double-check cache inside singleflight
		if !force {
			a.cacheMutex.Lock()
			if token, ok := a.tokens[domain]; ok {
				a.cacheMutex.Unlock()
				return map[string]string{AuthorizationHeader: BearerScheme + token}, nil
			}
			if header, ok := a.authHeaders[domain]; ok {
				a.cacheMutex.Unlock()
				return map[string]string{AuthorizationHeader: header}, nil
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

		return map[string]string{AuthorizationHeader: headerString}, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(map[string]string), nil
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
	token := header.Get(AuthorizationHeader)
	if !strings.HasPrefix(token, BearerScheme) {
		return
	}

	domain, err := getDomain(target)
	if err != nil {
		a.logger.Warn("update token: invalid domain", "url", target, "error", err)
		return
	}

	a.cacheMutex.Lock()
	a.tokens[domain] = strings.TrimPrefix(token, BearerScheme)
	a.cacheMutex.Unlock()
}

// ClearToken removes any cached token/header for the target.
func (a *Authenticator) ClearToken(target string) {
	domain, err := getDomain(target)
	if err != nil {
		a.logger.Warn("clear token: invalid domain", "url", target, "error", err)
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
