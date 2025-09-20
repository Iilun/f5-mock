package handlers

import (
	"encoding/json"
	"github.com/iilun/f5-mock/internal/crypto"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/f5Validator"
	"io"
	"net/http"
	"path"
)

type CryptoCertHandler struct{}

func (h CryptoCertHandler) Route() string {
	return "/mgmt/tm/sys/crypto/cert"
}

func (h CryptoCertHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request) {

			// Read body
			bytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not read body")
				return
			}

			var request CryptoCommandRequest
			err = json.Unmarshal(bytes, &request)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid JSON body")
				return
			}

			err = f5Validator.Validate.Struct(request)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid request")
				return
			}

			if request.Command != "install" {
				f5Error(w, r, http.StatusBadRequest, "unsupported command")
				return
			}

			destPath := path.Join("/certs", request.Name)

			if cache.GlobalCache.Fs.Exists(destPath) {
				f5Error(w, r, http.StatusBadRequest, "dest path already exists")
				return
			}

			// Get previous file
			contents, err := cache.GlobalCache.Fs.ReadFile(request.FromLocalFile)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "could not read local file")
				return
			}

			// Check that content is a valid certificate
			if !crypto.IsValidPemCertificate(contents) {
				f5Error(w, r, http.StatusBadRequest, "invalid certificate file")
				return
			}

			_, err = cache.GlobalCache.Fs.WriteFile(destPath, contents)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not write cert file")
				return
			}
			return
		})
}

type CryptoCommandRequest struct {
	Command       string `json:"command" validate:"required"`
	Name          string `json:"name" validate:"required"`
	FromLocalFile string `json:"from-local-file" validate:"required,existingfile"`
	SecurityType  string `json:"securityType"`
}
