package handlers

import (
	"github.com/iilun/f5-mock/pkg/cache"
	"io"
	"net/http"
	"path"
)

type UploadHandler struct{}

func (h UploadHandler) Route() string {
	return "/mgmt/shared/file-transfer/uploads/{path}"
}

func (h UploadHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				f5Error(w, r, http.StatusMethodNotAllowed, "only POST allowed")
				return
			}

			err := checkContentType(r, "application/octet-stream")
			if err != nil {
				f5Error(w, r, http.StatusUnsupportedMediaType, "%v", err)
				return
			}

			uploadPath := r.PathValue("path")
			if uploadPath == "" {
				f5Error(w, r, http.StatusBadRequest, "invalid path")
				return
			}

			// Path is stored
			uploadPath = path.Join("/var/config/rest/downloads/", uploadPath)

			// Check if path not already exists
			if cache.GlobalCache.Fs.Exists(uploadPath) {
				f5Error(w, r, http.StatusBadRequest, "file already exists")
				return
			}

			toWrite, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not read request")
				return
			}

			_, err = cache.GlobalCache.Fs.WriteFile(uploadPath, toWrite)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not write request")
				return
			}
		})
}
