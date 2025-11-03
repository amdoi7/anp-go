// This example demonstrates using the high-level ANP session to fetch documents
// and invoke tools for a mapping service.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openanp/anp-go/anp_crawler"
	"github.com/openanp/anp-go/session"
)

const (
	docURL          = "https://agent-connect.ai/mcp/agents/amap/ad.json"
	interfaceURL    = "https://agent-connect.ai/mcp/agents/api/amap.json"
	jsonrpcEndpoint = "https://agent-connect.ai/mcp/agents/tools/amap"
	didDocument     = "examples/did_public/public-did-doc.json"
	privateKeyFile  = "examples/did_public/public-private-key.pem"
	defaultMethod   = "maps_weather"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("example failed:", err)
		os.Exit(1)
	}
}

func run() error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	didDocPath, privateKeyPath, err := resolveCredentialPaths(wd)
	if err != nil {
		return fmt.Errorf("locate credentials: %w", err)
	}

	sess, err := session.New(session.Config{
		DIDDocumentPath: didDocPath,
		PrivateKeyPath:  privateKeyPath,
		HTTP:            session.HTTPConfig{Timeout: 20 * time.Second},
	})
	if err != nil {
		return fmt.Errorf("create ANP session: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("\n--- Fetching Agent Description Document ---")
	docEntry, err := sess.Fetch(ctx, docURL)
	if err != nil {
		return fmt.Errorf("fetch doc: %w", err)
	}
	renderDocumentSummary(docEntry)

	fmt.Println("\n--- Fetching Interface Document ---")
	interfaceDoc, err := sess.Fetch(ctx, interfaceURL)
	if err != nil {
		return fmt.Errorf("fetch interface: %w", err)
	}
	renderDocumentSummary(interfaceDoc)

	fmt.Println("\n--- Executing Tool Call: maps_weather ---")
	toolArgs := map[string]any{"city": "杭州市"}
	result, err := session.ExecuteTool(ctx, interfaceDoc, defaultMethod, toolArgs)
	if err != nil {
		return err
	}
	prettyResult, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(prettyResult))

	fmt.Println("\n--- Executing Direct JSON-RPC Call: maps_weather ---")
	rpcPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "demo",
		"method":  defaultMethod,
		"params":  map[string]any{"city": "上海市"},
	}
	rpcResp, err := sess.Invoke(ctx, http.MethodPost, jsonrpcEndpoint, map[string]string{"Content-Type": "application/json"}, rpcPayload)
	if err != nil {
		return fmt.Errorf("invoke json-rpc: %w", err)
	}
	prettyRPC, _ := json.MarshalIndent(json.RawMessage(rpcResp.Body), "", "  ")
	fmt.Println(string(prettyRPC))

	return nil
}

func resolveCredentialPaths(startDir string) (string, string, error) {
	root, err := findModuleRoot(startDir)
	if err != nil {
		return "", "", fmt.Errorf("find module root: %w", err)
	}

	didDocPath := filepath.Join(root, didDocument)
	if _, err := os.Stat(didDocPath); err != nil {
		return "", "", fmt.Errorf("stat DID document %s: %w", didDocPath, err)
	}

	privateKeyPath := filepath.Join(root, privateKeyFile)
	if _, err := os.Stat(privateKeyPath); err != nil {
		return "", "", fmt.Errorf("stat private key %s: %w", privateKeyPath, err)
	}

	return didDocPath, privateKeyPath, nil
}

func findModuleRoot(startDir string) (string, error) {
	dir := startDir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found from %s", startDir)
}

func renderDocumentSummary(doc *session.Document) {
	fmt.Println("Content:")
	fmt.Println(doc.ContentString())

	interfaces := session.ListInterfaces(doc)
	fmt.Printf("Interface Entries (%d):\n", len(interfaces))
	if len(interfaces) == 0 {
		fmt.Println("  (none)")
	}
	converter := anp_crawler.NewANPInterfaceConverter()
	for idx, entry := range interfaces {
		fmt.Printf("  [%d] type=%q protocol=%q", idx, entry.Type, entry.Protocol)
		if entry.URL != "" {
			fmt.Printf(" url=%s", entry.URL)
		}
		if entry.Description != "" {
			fmt.Printf(" description=%q", entry.Description)
		}
		fmt.Println()
		if len(entry.Content) > 0 {
			fmt.Println("    Inline content:")
			fmt.Println("    ", string(entry.Content))
		}
		if tool, _ := converter.ConvertToANPTool(entry); tool != nil {
			fmt.Printf("    ANP Tool: %s\n", tool.Function.Name)
		}
	}

	agents := session.ListAgents(doc)
	fmt.Printf("Agent Entries (%d):\n", len(agents))
	if len(agents) == 0 {
		fmt.Println("  (none)")
	}
	for idx, agent := range agents {
		fmt.Printf("  [%d] %s -> %s\n", idx, agent.Name, agent.URL)
		if agent.Description != "" {
			fmt.Println("    Description:", agent.Description)
		}
		if agent.Rating != 0 || agent.UsageCount != 0 || agent.ReviewCount != 0 {
			fmt.Printf("    Stats: rating=%.2f usage=%d reviews=%d\n", agent.Rating, agent.UsageCount, agent.ReviewCount)
		}
	}
}
