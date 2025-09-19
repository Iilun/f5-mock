package handlers

import (
	"F5Mock/internal/crypto"
	"F5Mock/pkg/cache"
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"io"
	"net/http"
)

type CryptoKeyHandler struct{}

func (h CryptoKeyHandler) Route() string {
	return "/mgmt/tm/sys/crypto/key"
}

func (h CryptoKeyHandler) Handler() IControlHandlerFunc {
	return authenticatedIControlRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request, version int) {

			// Read body
			bytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not read body")
				return
			}

			var request CryptoCommandRequest
			err = json.Unmarshal(bytes, &request)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid JSON body")
				return
			}

			validate := validator.New(validator.WithRequiredStructEnabled())

			err = validate.Struct(request)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid request")
				return
			}

			if request.Command != "install" {
				f5Error(w, http.StatusBadRequest, "unsupported command")
				return
			}

			if cache.GlobalCache.Fs.Exists(request.Name) {
				f5Error(w, http.StatusBadRequest, "dest path already exists")
				return
			}

			// Get previous file
			contents, err := cache.GlobalCache.Fs.ReadFile(request.FromLocalFile)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "could not read local file")
				return
			}

			// Check that content is a valid certificate
			if !crypto.IsValidPem(contents) {
				f5Error(w, http.StatusBadRequest, "invalid pem file")
				return
			}

			_, err = cache.GlobalCache.Fs.WriteFile(request.Name, contents)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not write key file")
				return
			}
			return
		})
}
