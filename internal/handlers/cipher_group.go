package handlers

import (
	"encoding/json"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/models"
	"net/http"
	"slices"
)

type CipherGroupHandler struct{}

func (h CipherGroupHandler) Route() string {
	return "/mgmt/tm/ltm/cipher/group/{group}"
}

func (h CipherGroupHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(
		func(w http.ResponseWriter, r *http.Request) {
			// Partition is ignored for groups
			_, group, err := parsePath(r.PathValue("group"))
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "%v", err.Error())
				return
			}

			if !slices.Contains(cache.GlobalCache.CipherGroups, group) {
				f5Error(w, r, http.StatusNotFound, "group not found")
				return
			}

			switch r.Method {
			case http.MethodGet:

				cg := models.CipherGroup{
					Kind: "tm:ltm:cipher:group:groupstate",
					Name: group,
				}

				respBytes, err := json.Marshal(cg)
				if err != nil {
					f5Error(w, r, http.StatusInternalServerError, "could not marshal")
					return
				}

				_, err = w.Write(respBytes)
				if err != nil {
					f5Error(w, r, http.StatusInternalServerError, "could not write response")
					return
				}
				break
			default:
				f5Error(w, r, http.StatusMethodNotAllowed, "invalid method")
				return
			}
		})
}
