// Hotel booking walkthrough using the high-level ANP session API.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"anp/anp_crawler"
	"anp/session"
)

const (
	navigationDocURL   = "https://agent-navigation.com/ad.json"
	toolCategoryDocURL = "https://agent-navigation.com/tool/ad.json"
	taskCategoryDocURL = "https://agent-navigation.com/task/ad.json"
	hotelAgentDocURL   = "https://agent-connect.ai/agents/hotel-assistant/ad.json"
	hotelInterfaceURL  = "https://agent-connect.ai/api/hotel-service-interface.json"

	didDocumentPathRel = "examples/did_public/public-did-doc.json"
	privateKeyPathRel  = "examples/did_public/public-private-key.pem"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("hotel booking walkthrough failed:", err)
		os.Exit(1)
	}
}

func run() error {
	didDocPath, privateKeyPath, err := resolveCredentialPaths()
	if err != nil {
		return fmt.Errorf("locate credentials: %w", err)
	}

	sess, err := session.New(session.Config{
		DIDDocumentPath: didDocPath,
		PrivateKeyPath:  privateKeyPath,
		HTTP:            session.HTTPConfig{Timeout: 30 * time.Second},
	})
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fmt.Println("\n=== Fetch agent directory ===")
	if err := fetchAndPrint(ctx, sess, navigationDocURL); err != nil {
		return err
	}

	fmt.Println("\n=== Fetch tool-category listing ===")
	if err := fetchAndPrint(ctx, sess, toolCategoryDocURL); err != nil {
		return err
	}

	fmt.Println("\n=== Fetch task-category listing ===")
	if err := fetchAndPrint(ctx, sess, taskCategoryDocURL); err != nil {
		return err
	}

	fmt.Println("\n=== Fetch hotel assistant agent description ===")
	if err := fetchAndPrint(ctx, sess, hotelAgentDocURL); err != nil {
		return err
	}

	fmt.Println("\n=== Fetch hotel OpenRPC interface ===")
	hotelInterfaceDoc, err := sess.Fetch(ctx, hotelInterfaceURL)
	if err != nil {
		return fmt.Errorf("fetch hotel interface: %w", err)
	}
	renderDocument(hotelInterfaceDoc)

	fmt.Println("\n=== Search Quanji hotels in Beijing (query text) ===")
	firstSearch := map[string]any{"searchCriteria": map[string]any{
		"cityName":     "北京",
		"checkInDate":  "2025-11-03",
		"checkOutDate": "2025-11-04",
		"queryText":    "全季望京",
		"pageSize":     10,
	}}
	if err := executeTool(ctx, hotelInterfaceDoc, "searchHotelList", firstSearch); err != nil {
		return err
	}

	fmt.Println("\n=== Search Quanji hotels in Beijing (brand filter) ===")
	secondSearch := map[string]any{"searchCriteria": map[string]any{
		"checkInDate":  "2025-11-03",
		"checkOutDate": "2025-11-04",
		"cityName":     "北京",
		"brands":       "全季",
		"pageSize":     10,
	}}
	if err := executeTool(ctx, hotelInterfaceDoc, "searchHotelList", secondSearch); err != nil {
		return err
	}

	fmt.Println("\n=== Query room and rate plans for hotel 10044523 ===")
	roomParams := map[string]any{
		"hotelID":      10044523,
		"checkInDate":  "2025-11-03",
		"checkOutDate": "2025-11-04",
	}
	if err := executeTool(ctx, hotelInterfaceDoc, "queryRoomAndRatePlan", roomParams); err != nil {
		return err
	}

	fmt.Println("\n=== Direct JSON-RPC call to book ===")
	rpcRequest := map[string]any{
		"jsonrpc": "2.0",
		"id":      "booking",
		"method":  "bookHotel",
		"params": map[string]any{
			"hotelID":      10044523,
			"checkInDate":  "2025-11-03",
			"checkOutDate": "2025-11-04",
			"roomType":     "deluxe",
		},
	}
	rpcResp, err := sess.Invoke(ctx, http.MethodPost, hotelInterfaceURL, map[string]string{"Content-Type": "application/json"}, rpcRequest)
	if err != nil {
		return fmt.Errorf("invoke bookHotel: %w", err)
	}
	prettyResp, _ := json.MarshalIndent(json.RawMessage(rpcResp.Body), "", "  ")
	fmt.Println(string(prettyResp))

	return nil
}

func fetchAndPrint(ctx context.Context, sess *session.Session, url string) error {
	doc, err := sess.Fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	renderDocument(doc)
	return nil
}

func renderDocument(doc *session.Document) {
	fmt.Println("  Content:")
	fmt.Println(doc.ContentString())

	interfaces := session.ListInterfaces(doc)
	fmt.Printf("  Interface Entries (%d):\n", len(interfaces))
	if len(interfaces) == 0 {
		fmt.Println("    (none)")
	}
	converter := anp_crawler.NewANPInterfaceConverter()
	for idx, entry := range interfaces {
		fmt.Printf("    [%d] type=%q protocol=%q", idx, entry.Type, entry.Protocol)
		if entry.URL != "" {
			fmt.Printf(" url=%s", entry.URL)
		}
		if entry.Description != "" {
			fmt.Printf(" description=%q", entry.Description)
		}
		fmt.Println()
		if len(entry.Content) > 0 {
			pretty, _ := json.MarshalIndent(json.RawMessage(entry.Content), "      ", "  ")
			fmt.Println(string(pretty))
		}
		if tool, _ := converter.ConvertToANPTool(entry); tool != nil {
			fmt.Printf("      ANP Tool: %s\n", tool.Function.Name)
		}
	}

	agents := session.ListAgents(doc)
	fmt.Printf("  Agent Entries (%d):\n", len(agents))
	if len(agents) == 0 {
		fmt.Println("    (none)")
	}
	for idx, agent := range agents {
		fmt.Printf("    [%d] %s -> %s\n", idx, agent.Name, agent.URL)
		if agent.Description != "" {
			fmt.Println("      Description:", agent.Description)
		}
		if agent.Rating != 0 || agent.UsageCount != 0 || agent.ReviewCount != 0 {
			fmt.Printf("      Stats: rating=%.2f usage=%d reviews=%d\n", agent.Rating, agent.UsageCount, agent.ReviewCount)
		}
	}
}

func executeTool(ctx context.Context, doc *session.Document, method string, params map[string]any) error {
	result, err := session.ExecuteTool(ctx, doc, method, params)
	if err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("    RPC %s result:\n%s\n", method, string(pretty))
	return nil
}

func resolveCredentialPaths() (string, string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("get working directory: %w", err)
	}

	moduleRoot, err := findModuleRoot(wd)
	if err != nil {
		return "", "", fmt.Errorf("find module root: %w", err)
	}

	didDocPath := filepath.Join(moduleRoot, didDocumentPathRel)
	if _, err := os.Stat(didDocPath); err != nil {
		return "", "", fmt.Errorf("stat DID document %s: %w", didDocPath, err)
	}

	privateKeyPath := filepath.Join(moduleRoot, privateKeyPathRel)
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
		nestedRoot := filepath.Join(dir, "anp-go")
		if _, err := os.Stat(filepath.Join(nestedRoot, "go.mod")); err == nil {
			return nestedRoot, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found from %s", startDir)
}
