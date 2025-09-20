package main

import (
	"github.com/iilun/f5-mock/internal/handlers"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"net/http"
	"os"
)

func main() {

	logger := log.New(os.Getenv("F5_DEBUG") != "")
	defer logger.Close()
	log.Default = logger

	_, err := cache.New(os.Getenv("F5_SEED_FILE"))
	if err != nil {
		logger.Fatal(err.Error())
	}

	handlers.RegisterHandler(handlers.LoginHandler{}, logger)
	handlers.RegisterHandler(handlers.AS3Handler{}, logger)
	handlers.RegisterHandler(handlers.ClientSSLListHandler{}, logger)
	handlers.RegisterHandler(handlers.ClientSSLHandler{}, logger)
	handlers.RegisterHandler(handlers.UploadHandler{}, logger)
	handlers.RegisterHandler(handlers.CryptoCertHandler{}, logger)
	handlers.RegisterHandler(handlers.CryptoKeyHandler{}, logger)
	handlers.RegisterHandler(handlers.SSLCertHandler{}, logger)

	certFilePath := os.Getenv("F5_CERT_PATH")
	if certFilePath == "" {
		certFilePath = "/etc/ssl/f5/cert.pem"
	}

	keyFilePath := os.Getenv("F5_KEY_PATH")
	if keyFilePath == "" {
		keyFilePath = "/etc/ssl/f5/key.pem"
	}

	err = http.ListenAndServeTLS(":4443", certFilePath, keyFilePath, nil)
	if err != nil {
		logger.Fatal(err.Error())
	}
}
