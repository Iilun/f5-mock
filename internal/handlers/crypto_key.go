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

type CryptoKeyHandler struct{}

func (h CryptoKeyHandler) Route() string {
	return "/mgmt/tm/sys/crypto/key"
}

func (h CryptoKeyHandler) Handler() http.HandlerFunc {
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

			destPath := path.Join("/keys", request.Name)

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
			if !crypto.IsValidPem(contents) {
				f5Error(w, r, http.StatusBadRequest, "invalid pem file")
				return
			}

			logger := loggerFromRequest(r)
			logger.Debug("Writing key to %s", destPath)

			_, err = cache.GlobalCache.Fs.WriteFile(destPath, contents)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not write key file")
				return
			}
			return
		})
}
