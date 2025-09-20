package handlers

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/iilun/f5-mock/internal/crypto"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/f5Validator"
	"github.com/iilun/f5-mock/pkg/models"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

type ClientSSLListHandler struct{}

func (h ClientSSLListHandler) Route() string {
	return "/mgmt/tm/ltm/profile/client-ssl"
}

func (h ClientSSLListHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Parse request params
			queryParams := r.URL.Query()
			fieldSelect := queryParams.Get("$select")
			filter := queryParams.Get("$filter")

			var partition string
			var found bool

			if filter != "" {
				partition, found = strings.CutPrefix(filter, "partition eq ")
				if !found {
					f5Error(w, r, http.StatusBadRequest, "unsupported $filter")
					return
				}
			}

			filteredItems := []map[string]any{}

			for _, profile := range cache.GlobalCache.ClientSSLProfiles {
				if partition == "" || profile.Partition == partition {
					filteredProfile, err := filterFields(*profile, fieldSelect)
					if err != nil {
						f5Error(w, r, http.StatusInternalServerError, "error while filtering")
						return
					}
					filteredItems = append(filteredItems, filteredProfile)
				}
			}

			response := ClientSSLListResponse{Items: filteredItems}

			respBytes, err := json.Marshal(response)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not marshal response")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not write response")
				return
			}
			break
		case http.MethodPost:
			if r.Header.Get("Content-Type") != "application/json" {
				f5Error(w, r, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not read request")
				return
			}
			var newProfile models.ClientSSLProfile
			err = json.Unmarshal(bodyBytes, &newProfile)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid post request")
				return
			}

			err = f5Validator.Validate.Struct(newProfile)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid request")
				return
			}

			version, ok := r.Context().Value(log.ContextVersion).(int)
			if !ok {
				f5Error(w, r, http.StatusInternalServerError, "invalid version")
				return
			}

			err = validateCert(newProfile.Cert, version)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid cert: %s", err.Error())
				return
			}

			foundProfile := findProfile(newProfile.Partition, newProfile.Name)
			if foundProfile != nil {
				f5Error(w, r, http.StatusBadRequest, "profile already exists")
				return
			}

			logger := loggerFromRequest(r)

			logger.Debug("Added %s profile", newProfile.Name)

			cache.GlobalCache.ClientSSLProfiles = append(cache.GlobalCache.ClientSSLProfiles, &newProfile)

			respBytes, err := json.Marshal(newProfile)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not marshal response")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not write response")
				return
			}

			break
		default:
			f5Error(w, r, http.StatusNotFound, "invalid method")
			return
		}
	})
}

func filterFields(profile models.ClientSSLProfile, selectField string) (map[string]any, error) {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	var asMap map[string]any
	err = json.Unmarshal(bytes, &asMap)
	if err != nil {
		return nil, err
	}
	asMap["kind"] = "tm:ltm:profile:client-ssl:client-sslstate"
	if selectField != "" {
		filteredMap := make(map[string]any)
		for key, value := range asMap {
			if key == selectField {
				filteredMap[key] = value
			}
		}
		return filteredMap, nil
	}
	return asMap, nil
}

type ClientSSLListResponse struct {
	// Items is a map because results can be filtered to omit fields
	Items []map[string]any `json:"items"`
}

type ClientSSLHandler struct{}

func (h ClientSSLHandler) Route() string {
	return "/mgmt/tm/ltm/profile/client-ssl/{profile}"
}

func (h ClientSSLHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {
		partition, profileName, err := parsePath(r.PathValue("profile"))

		if err != nil {
			f5Error(w, r, http.StatusBadRequest, "%v", err)
			return
		}

		foundProfile := findProfile(partition, profileName)

		if foundProfile == nil {
			f5Error(w, r, http.StatusNotFound, "could not find profile %s for partition %s", profileName, partition)
			return
		}

		switch r.Method {
		case http.MethodGet:
			asMap, err := filterFields(*foundProfile, r.URL.Query().Get("$select"))
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not select field: %v", err)
				return
			}

			respBytes, err := json.Marshal(asMap)
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
		case http.MethodPatch:
			if err = checkContentType(r, "application/json"); err != nil {
				f5Error(w, r, http.StatusUnsupportedMediaType, "%v", err)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not read request")
				return
			}

			var patchRequest PatchClientSSLProfile

			err = json.Unmarshal(bodyBytes, &patchRequest)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid patch request")
				return
			}

			if err = f5Validator.Validate.Struct(patchRequest); err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid request: %v", err)
				return
			}

			version, ok := r.Context().Value(log.ContextVersion).(int)
			if !ok {
				f5Error(w, r, http.StatusInternalServerError, "invalid version")
				return
			}

			if err = validateCert(patchRequest.Cert, version); err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid cert: %s", err.Error())
				return
			}

			if patchRequest.Cert != "" {
				foundProfile.Cert = patchRequest.Cert
			}

			if patchRequest.Key != "" {
				foundProfile.Key = patchRequest.Key
			}

			respBytes, err := json.Marshal(*foundProfile)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not marshal response")
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

type PatchClientSSLProfile struct {
	DefaultsFrom string `json:"defaultsFrom"`
	Cert         string `json:"cert" validate:"existingcertfile"`
	Key          string `json:"key" validate:"existingkeyfile"`
}

func findProfile(partition, name string) *models.ClientSSLProfile {
	for i := range cache.GlobalCache.ClientSSLProfiles {
		profile := cache.GlobalCache.ClientSSLProfiles[i]
		if profile.Partition == partition && profile.Name == name {
			return profile
		}
	}
	return nil
}

func validateCert(path string, version int) error {
	if version >= 17 {
		return nil
	}
	// Check ECDSA certs not supported
	certBytes, err := cache.GlobalCache.Fs.ReadFile(filepath.Join("/certs", path))
	if err != nil {
		return err
	}

	cert, err := crypto.ParsePemCertificate(certBytes)
	if err != nil {
		return err
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return errors.New("must have RSA certificate/key pair.")
	}

	return nil
}
