package anp_auth

import (
	"fmt"
	"net/http"
)

// Transport wraps an http.RoundTripper and automatically adds DID-WBA authentication.
type Transport struct {
	Base          http.RoundTripper
	Authenticator *Authenticator
}

// RoundTrip implements http.RoundTripper by adding authentication headers.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Authenticator == nil {
		return nil, fmt.Errorf("authenticator is required")
	}

	headers, err := t.Authenticator.GenerateHeader(req.URL.String())
	if err != nil {
		return nil, fmt.Errorf("generating auth header: %w", err)
	}

	clonedReq := req.Clone(req.Context())
	for k, v := range headers {
		clonedReq.Header.Set(k, v)
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	resp, err := base.RoundTrip(clonedReq)
	if err != nil {
		return nil, err
	}

	t.Authenticator.UpdateFromResponse(req.URL.String(), resp.Header)
	return resp, nil
}

// NewClient creates an HTTP client with automatic DID-WBA authentication.
func NewClient(authenticator *Authenticator) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Authenticator: authenticator,
		},
	}
}

// NewClientWithTransport creates an HTTP client with a custom base transport
// and automatic DID-WBA authentication.
func NewClientWithTransport(authenticator *Authenticator, base http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Base:          base,
			Authenticator: authenticator,
		},
	}
}
