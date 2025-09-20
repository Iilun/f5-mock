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

func (h SSLCertHandler) Handler() IControlHandlerFunc {
	return authenticatedIControlRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request, version int) {
			switch r.Method {
			case http.MethodGet:
				partition, certFile, err := parsePath(r.PathValue("path"))

				if err != nil {
					f5Error(w, http.StatusBadRequest, err.Error())
					return
				}

				destPath := path.Join("certs", partition, certFile)

				contents, err := cache.GlobalCache.Fs.ReadFile(destPath)

				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						f5Error(w, http.StatusNotFound, err.Error())
					} else {
						f5Error(w, http.StatusBadRequest, err.Error())
					}
					return
				}

				resp := SSLCertResponse{Cert: string(contents)}

				respBytes, err := json.Marshal(resp)
				if err != nil {
					f5Error(w, http.StatusInternalServerError, err.Error())
					return
				}

				_, err = w.Write(respBytes)
				if err != nil {
					f5Error(w, http.StatusInternalServerError, err.Error())
					return
				}
				return
			}
		})
}

type SSLCertResponse struct {
	Cert string `json:"cert"`
}
