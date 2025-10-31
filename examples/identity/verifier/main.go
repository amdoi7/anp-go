package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"anp/anp_auth"
)

func main() {
	var (
		didDocPath  string
		privatePath string
		target      string
	)

	flag.StringVar(&didDocPath, "doc", "examples/did_public/public-did-doc.json", "Path to DID document")
	flag.StringVar(&privatePath, "key", "examples/did_public/public-private-key.pem", "Path to private key")
	flag.StringVar(&target, "target", "https://agent-connect.ai/api", "Service domain/URL")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("get working directory: %v", err)
	}

	if !filepath.IsAbs(didDocPath) {
		didDocPath = filepath.Join(wd, didDocPath)
	}
	if !filepath.IsAbs(privatePath) {
		privatePath = filepath.Join(wd, privatePath)
	}

	auth, err := anp_auth.NewAuthenticator(anp_auth.Config{
		DIDDocumentPath: didDocPath,
		PrivateKeyPath:  privatePath,
	})
	if err != nil {
		log.Fatalf("create authenticator: %v", err)
	}

	payload, err := auth.GenerateJSON(target)
	if err != nil {
		log.Fatalf("generate json: %v", err)
	}
	payloadBytes, err := payload.Marshal()
	if err != nil {
		log.Fatalf("marshal json: %v", err)
	}

	didBytes, err := os.ReadFile(didDocPath)
	if err != nil {
		log.Fatalf("read did doc: %v", err)
	}
	var doc anp_auth.DIDWBADocument
	if err := json.Unmarshal(didBytes, &doc); err != nil {
		log.Fatalf("decode did doc: %v", err)
	}

	ok, msg, err := anp_auth.VerifyAuthJSONBytes(payloadBytes, &doc, "agent-connect.ai")
	if err != nil {
		log.Fatalf("verify json: %v", err)
	}

	fmt.Printf("verification ok=%v msg=%s\n", ok, msg)
}
