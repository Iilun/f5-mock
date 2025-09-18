package main

import (
	"F5Mock/pkg/cache"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func main() {
	_, err := cache.New()
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/toto", totoHandler)
	http.HandleFunc("/tata", tataHandler)

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
