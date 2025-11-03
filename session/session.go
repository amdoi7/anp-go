// Package session provides a high-level façade that combines authentication, transport, and parsing for ANP documents.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/openanp/anp-go/anp_auth"
	"github.com/openanp/anp-go/anp_crawler"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

const defaultHTTPTimeout = 30 * time.Second

// Config describes how a high-level ANP session should be built.
// Either provide an Authenticator or the paths to a DID document and private key.
type Config struct {
	DIDDocumentPath string
	PrivateKeyPath  string
	Authenticator   *anp_auth.Authenticator

	HTTP   HTTPConfig
	Parser ParserConfig

	MaxConcurrent int
	Logger        *slog.Logger
}

// HTTPConfig customises the HTTP transport used by the session.
type HTTPConfig struct {
	Client  *http.Client
	Timeout time.Duration
}

// ParserConfig allows injecting custom parser/converter implementations.
type ParserConfig struct {
	Parser    anp_crawler.Parser
	Converter *anp_crawler.ANPInterfaceConverter
}

// Session orchestrates authenticated HTTP requests and document parsing for ANP.
type Session struct {
	authenticator *anp_auth.Authenticator
	client        anp_crawler.Client
	parser        anp_crawler.Parser
	converter     *anp_crawler.ANPInterfaceConverter
	logger        *slog.Logger
	sem           *semaphore.Weighted
}

// Document stores the result of fetching and parsing an ANP document.
type Document struct {
	URL         string
	StatusCode  int
	ContentType string
	Raw         []byte
	Result      *anp_crawler.ParseResult
	Tools       []*anp_crawler.ANPTool
	Interfaces  []*anp_crawler.ANPInterface
}

// New creates a Session with sensible defaults.
func New(cfg Config) (*Session, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	anp_crawler.SetLogger(logger)

	authenticator := cfg.Authenticator
	if authenticator == nil {
		auth, err := anp_auth.NewAuthenticator(
			anp_auth.WithDIDCfgPaths(cfg.DIDDocumentPath, cfg.PrivateKeyPath),
		)
		if err != nil {
			return nil, err
		}
		authenticator = auth
	}

	httpClient := cfg.HTTP.Client
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if cfg.HTTP.Timeout > 0 {
		httpClient.Timeout = cfg.HTTP.Timeout
	} else if httpClient.Timeout == 0 {
		httpClient.Timeout = defaultHTTPTimeout
	}

	client := anp_crawler.NewClient(authenticator, anp_crawler.WithHTTPClient(httpClient))

	parser := cfg.Parser.Parser
	if parser == nil {
		parser = anp_crawler.NewJSONParser()
	}

	converter := cfg.Parser.Converter
	if converter == nil {
		converter = anp_crawler.NewANPInterfaceConverter()
	}

	maxConc := cfg.MaxConcurrent
	if maxConc <= 0 {
		maxConc = 5
	}

	return &Session{
		authenticator: authenticator,
		client:        client,
		parser:        parser,
		converter:     converter,
		logger:        logger,
		sem:           semaphore.NewWeighted(int64(maxConc)),
	}, nil
}

// Authenticator exposes the underlying authenticator for advanced use cases.
func (s *Session) Authenticator() *anp_auth.Authenticator {
	return s.authenticator
}

// Client returns the low-level client used by the session.
func (s *Session) Client() anp_crawler.Client {
	return s.client
}

// Fetch retrieves and parses a single document.
func (s *Session) Fetch(ctx context.Context, url string) (*Document, error) {
	resp, err := s.client.Fetch(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}

	result, err := s.parser.Parse(ctx, resp.Body, resp.ContentType, url)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}

	doc := &Document{
		URL:         url,
		StatusCode:  resp.StatusCode,
		ContentType: resp.ContentType,
		Raw:         resp.Body,
		Result:      result,
	}

	for _, entry := range result.Interfaces {
		var toolName string
		if tool, err := s.converter.ConvertToANPTool(entry); err == nil && tool != nil {
			doc.Tools = append(doc.Tools, tool)
			toolName = tool.Function.Name
		} else if err != nil {
			s.logger.Debug("tool conversion failed", "url", url, "error", err)
		}

		if toolName == "" {
			toolName = entry.MethodName
			if toolName == "" {
				toolName = entry.Type
			}
		}

		iface := anp_crawler.NewANPInterface(toolName, entry, s.client)
		if iface != nil {
			doc.Interfaces = append(doc.Interfaces, iface)
		}
	}

	return doc, nil
}

// FetchBatch fetches multiple documents concurrently.
func (s *Session) FetchBatch(ctx context.Context, urls []string) ([]*Document, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	results := make([]*Document, len(urls))
	g, ctx := errgroup.WithContext(ctx)

	for i, url := range urls {
		i, url := i, url

		if err := s.sem.Acquire(ctx, 1); err != nil {
			return nil, err
		}

		g.Go(func() error {
			defer s.sem.Release(1)
			doc, err := s.Fetch(ctx, url)
			if err != nil {
				return err
			}
			results[i] = doc
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

// Invoke performs a generic HTTP request using the session client.
func (s *Session) Invoke(ctx context.Context, method, target string, headers map[string]string, body any) (*anp_crawler.Response, error) {
	if method == "" {
		method = http.MethodGet
	}
	return s.client.Fetch(ctx, method, target, headers, body)
}

// ListInterfaces returns the raw interface entries extracted from the document.
func ListInterfaces(doc *Document) []anp_crawler.InterfaceEntry {
	if doc == nil || doc.Result == nil {
		return nil
	}
	return doc.Result.Interfaces
}

// ListAgents returns the agent entries extracted from the document.
func ListAgents(doc *Document) []anp_crawler.AgentEntry {
	if doc == nil || doc.Result == nil {
		return nil
	}
	return doc.Result.Agents
}

// ContentString returns the document body as a UTF-8 string.
func (d *Document) ContentString() string {
	if d == nil {
		return ""
	}
	return string(d.Raw)
}

// NewFromAuthenticator is a convenience helper to create a session from an existing authenticator.
func NewFromAuthenticator(auth *anp_auth.Authenticator) (*Session, error) {
	if auth == nil {
		return nil, errors.New("anp/session: authenticator is nil")
	}
	return New(Config{Authenticator: auth})
}

// ExecuteTool searches for the specified method within the document interfaces and executes it.
func ExecuteTool(ctx context.Context, doc *Document, method string, params map[string]any) (map[string]any, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}
	for _, iface := range doc.Interfaces {
		if iface.Method == method {
			return iface.Execute(ctx, params)
		}
	}
	return nil, fmt.Errorf("method %s not available", method)
}
