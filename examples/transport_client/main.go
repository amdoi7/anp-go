package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/openanp/anp-go/anp_auth"
)

func main() {
	var (
		didDocPath  string
		privatePath string
		targetURL   string
	)

	flag.StringVar(&didDocPath, "doc", "examples/did_public/public-did-doc.json", "Path to DID document")
	flag.StringVar(&privatePath, "key", "examples/did_public/public-private-key.pem", "Path to private key")
	flag.StringVar(&targetURL, "url", "https://api.example.com/endpoint", "Target URL")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}

	if !filepath.IsAbs(didDocPath) {
		didDocPath = filepath.Join(wd, didDocPath)
	}
	if !filepath.IsAbs(privatePath) {
		privatePath = filepath.Join(wd, privatePath)
	}

	auth, err := anp_auth.NewAuthenticator(
		anp_auth.WithDIDCfgPaths(didDocPath, privatePath),
	)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	client := anp_auth.NewClient(auth)

	resp, err := client.Get(targetURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Status Code: %d\n", resp.StatusCode)

	if token := resp.Header.Get("Authorization"); token != "" {
		fmt.Printf("Received token: %s\n", token)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("Response body: %s\n", string(body))
	} else {
		fmt.Println("Response JSON:")
		prettyJSON, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(prettyJSON))
	}

	resp2, err := client.Get(targetURL)
	if err != nil {
		log.Fatalf("Second request failed: %v", err)
	}
	defer resp2.Body.Close()

	fmt.Printf("\nSecond request status: %s\n", resp2.Status)
	fmt.Println("(This request should use the cached bearer token)")
}
