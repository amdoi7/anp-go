package anp_crawler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"time"

	"github.com/bytedance/sonic"
	"github.com/openanp/anp-go/anp_auth"
)

// Client describes the capabilities required by the crawler to retrieve ANP documents.
type Client interface {
	Fetch(ctx context.Context, method, target string, headers map[string]string, body any) (*Response, error)
}

// Response represents the HTTP payload returned by the Client.Fetch call.
type Response struct {
	StatusCode  int
	URL         string
	ContentType string
	Encoding    string
	Header      http.Header
	Body        []byte
}

// httpClient is the default Client implementation that performs DID-authenticated HTTP requests.
type httpClient struct {
	httpClient    *http.Client
	authenticator *anp_auth.Authenticator
}

// ClientOption customises the behaviour of httpClient.
type ClientOption func(*httpClient)

// WithHTTPClient injects a custom http.Client.
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *httpClient) {
		if h != nil {
			c.httpClient = h
		}
	}
}

// NewClient constructs a DID-authenticated HTTP client.
func NewClient(authenticator *anp_auth.Authenticator, opts ...ClientOption) Client {
	c := &httpClient{
		authenticator: authenticator,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *httpClient) Fetch(ctx context.Context, method, target string, headers map[string]string, body any) (*Response, error) {
	if method == "" {
		method = http.MethodGet
	}

	reqHeaders := make(map[string]string)
	if headers != nil {
		maps.Copy(reqHeaders, headers)
	}

	var bodyReader io.Reader
	switch v := body.(type) {
	case nil:
	case []byte:
		bodyReader = bytes.NewReader(v)
		if _, ok := reqHeaders["Content-Type"]; !ok {
			reqHeaders["Content-Type"] = "application/json"
		}
	case io.Reader:
		bodyReader = v
	default:
		jsonBody, err := sonic.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
		if _, ok := reqHeaders["Content-Type"]; !ok {
			reqHeaders["Content-Type"] = "application/json"
		}
	}

	// Get auth header from the new authenticator
	authHeader, err := c.authenticator.GenerateHeader(target)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth header: %w", err)
	}
	maps.Copy(reqHeaders, authHeader)

	performRequest := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		for k, v := range reqHeaders {
			req.Header.Set(k, v)
		}

		return c.httpClient.Do(req)
	}

	resp, err := performRequest()
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Handle unauthorized status: clear token and retry
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		logger.Debug("authentication failed, refreshing token", "url", target)
		c.authenticator.ClearToken(target)

		refreshedAuthHeader, err := c.authenticator.GenerateHeaderForce(target)
		if err != nil {
			return nil, fmt.Errorf("refresh auth header: %w", err)
		}
		// Update the headers map for the retry
		maps.Copy(reqHeaders, refreshedAuthHeader)

		// Retry the request
		resp, err = performRequest()
		if err != nil {
			return nil, fmt.Errorf("retry request: %w", err)
		}
	}
	defer resp.Body.Close()

	// On success, check for a new JWT in the response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.authenticator.UpdateFromResponse(target, resp.Header)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		URL:         target,
		ContentType: resp.Header.Get("Content-Type"),
		Encoding:    resp.Header.Get("Content-Encoding"),
		Header:      resp.Header.Clone(),
		Body:        bodyBytes,
	}, nil
}
