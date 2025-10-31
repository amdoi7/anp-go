package main

import (
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
		format      string
	)

	flag.StringVar(&didDocPath, "doc", "examples/did_public/public-did-doc.json", "Path to DID document")
	flag.StringVar(&privatePath, "key", "examples/did_public/public-private-key.pem", "Path to private key")
	flag.StringVar(&target, "target", "https://agent-connect.ai/api", "Service domain/URL")
	flag.StringVar(&format, "format", "header", "Output format: header or json")
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

	switch format {
	case "header":
		header, err := auth.GenerateHeader(target)
		if err != nil {
			log.Fatalf("generate header: %v", err)
		}
		fmt.Println("Authorization header:", header["Authorization"])
	case "json":
		payload, err := auth.GenerateJSON(target)
		if err != nil {
			log.Fatalf("generate json: %v", err)
		}
		bytes, err := payload.Marshal()
		if err != nil {
			log.Fatalf("marshal json: %v", err)
		}
		fmt.Println(string(bytes))
	default:
		log.Fatalf("unknown format: %s", format)
	}
}
