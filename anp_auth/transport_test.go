package anp_auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport_RoundTrip(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("Expected Authorization header")
		}
		w.Header().Set("Authorization", "Bearer test-token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

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

	client := NewClient(auth)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if !called {
		t.Error("Expected server to be called")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestNewClient(t *testing.T) {
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

	client := NewClient(auth)
	if client == nil {
		t.Fatal("Expected client to be created")
	}

	if client.Transport == nil {
		t.Fatal("Expected transport to be set")
	}

	transport, ok := client.Transport.(*Transport)
	if !ok {
		t.Fatal("Expected transport to be *Transport")
	}

	if transport.Authenticator != auth {
		t.Error("Expected authenticator to be set")
	}
}

func TestNewClientWithTransport(t *testing.T) {
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

	baseTransport := http.DefaultTransport
	client := NewClientWithTransport(auth, baseTransport)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	transport, ok := client.Transport.(*Transport)
	if !ok {
		t.Fatal("Expected transport to be *Transport")
	}

	if transport.Base != baseTransport {
		t.Error("Expected base transport to be set")
	}

	if transport.Authenticator != auth {
		t.Error("Expected authenticator to be set")
	}
}
