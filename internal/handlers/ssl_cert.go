package handlers

import (
	"encoding/json"
	"errors"
	"github.com/iilun/f5-mock/pkg/cache"
	"io/fs"
	"net/http"
	"path"
)

type SSLCertHandler struct{}

func (h SSLCertHandler) Route() string {
	return "/mgmt/tm/sys/file/ssl-cert/{path}"
}

func (h SSLCertHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				partition, certFile, err := parsePath(r.PathValue("path"))

				if err != nil {
					f5Error(w, r, http.StatusBadRequest, "%v", err)
					return
				}

				destPath := path.Join("/certs", partition, certFile)

				contents, err := cache.GlobalCache.Fs.ReadFile(destPath)

				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						f5Error(w, r, http.StatusNotFound, "%v", err)
					} else {
						f5Error(w, r, http.StatusBadRequest, "%v", err)
					}
					return
				}

				resp := SSLCertResponse{Cert: string(contents)}

				respBytes, err := json.Marshal(resp)
				if err != nil {
					f5Error(w, r, http.StatusInternalServerError, "%v", err)
					return
				}

				_, err = w.Write(respBytes)
				if err != nil {
					f5Error(w, r, http.StatusInternalServerError, "%v", err)
					return
				}
				return
			}
		})
}

type SSLCertResponse struct {
	Cert string `json:"cert"`
}
