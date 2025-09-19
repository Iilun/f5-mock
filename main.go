package main

import (
	"F5Mock/internal/handlers"
	"F5Mock/pkg/cache"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// Example payload structure
type Payload struct {
	Message string `json:"message"`
	Number  int    `json:"number"`
}

func decodeBody(r *http.Request) (*Payload, error) {
	defer r.Body.Close()
	var p Payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func totoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	payload, err := decodeBody(r)
	if err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "Hello from /toto, got: %+v\n", payload)
}

func registerIControlHandler(handler handlers.IControlHandler) {
	f5Handler := handlers.WrapIControl(handler)
	registerF5Handler(f5Handler)
}

func registerF5Handler(handler handlers.F5Handler) {
	http.Handle(handler.Route(), handler.Handler())
}

func main() {
	_, err := cache.New(os.Getenv("F5_SEED_FILE"))
	if err != nil {
		log.Fatal(err)
	}

	registerF5Handler(handlers.LoginHandler{})
	registerF5Handler(handlers.AS3Handler{})
	registerIControlHandler(handlers.ClientSSLListHandler{})
	registerIControlHandler(handlers.ClientSSLHandler{})
	registerIControlHandler(handlers.UploadHandler{})
	registerIControlHandler(handlers.CryptoCertHandler{})
	registerIControlHandler(handlers.CryptoKeyHandler{})
	registerIControlHandler(handlers.SSLCertHandler{})

	certFilePath := os.Getenv("F5_CERT_PATH")
	if certFilePath == "" {
		certFilePath = "/etc/ssl/f5/cert.pem"
	}

	keyFilePath := os.Getenv("F5_KEY_PATH")
	if keyFilePath == "" {
		keyFilePath = "/etc/ssl/f5/key.pem"
	}

	log.Fatal(http.ListenAndServeTLS(":4443", certFilePath, keyFilePath, nil))
}
