package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/openanp/anp-go/anp_auth"
)

func main() {
	jwtPublicKeyPEM := os.Getenv("JWT_PUBLIC_KEY")
	jwtPrivateKeyPEM := os.Getenv("JWT_PRIVATE_KEY")

	if jwtPublicKeyPEM == "" || jwtPrivateKeyPEM == "" {
		log.Fatal("JWT_PUBLIC_KEY and JWT_PRIVATE_KEY environment variables are required")
	}

	nonceValidator := anp_auth.NewMemoryNonceValidator(6 * time.Minute)

	verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
		JWTPublicKeyPEM:       []byte(jwtPublicKeyPEM),
		JWTPrivateKeyPEM:      []byte(jwtPrivateKeyPEM),
		NonceValidator:        nonceValidator,
		AccessTokenExpiration: 60 * time.Minute,
		TimestampExpiration:   5 * time.Minute,
		DIDCacheExpiration:    15 * time.Minute,
	})
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "This is a public endpoint",
		})
	})

	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		did, ok := anp_auth.DIDFromContext(r.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "This is a protected endpoint",
			"did":     did,
		})
	})

	protectedMux.HandleFunc("/api/admin", anp_auth.RequireSpecificDID("did:wba:admin.example.com")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "This is an admin-only endpoint",
			})
		}),
	).ServeHTTP)

	mux.Handle("/api/", anp_auth.Middleware(verifier)(protectedMux))

	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)
	fmt.Println("Public endpoint: /public")
	fmt.Println("Protected endpoint: /api/profile")
	fmt.Println("Admin endpoint: /api/admin")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
