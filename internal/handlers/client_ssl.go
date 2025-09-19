package handlers

import (
	"F5Mock/internal/crypto"
	"F5Mock/pkg/cache"
	"F5Mock/pkg/models"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

type ClientSSLListHandler struct{}

func (h ClientSSLListHandler) Route() string {
	return "/mgmt/tm/ltm/profile/client-ssl"
}

func (h ClientSSLListHandler) Handler() IControlHandlerFunc {
	return authenticatedIControlRequestMiddleware(func(w http.ResponseWriter, r *http.Request, version int) {
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
					f5Error(w, http.StatusBadRequest, "unsupported $filter")
					return
				}
			}

			filteredItems := []map[string]any{}

			for _, profile := range cache.GlobalCache.ClientSSLProfiles {
				if partition == "" || profile.Partition == partition {
					filteredProfile, err := filterFields(*profile, fieldSelect)
					if err != nil {
						f5Error(w, http.StatusInternalServerError, "error while filtering")
						return
					}
					filteredItems = append(filteredItems, filteredProfile)
				}
			}

			response := ClientSSLListResponse{Items: filteredItems}

			respBytes, err := json.Marshal(response)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not marshal response")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not write response")
				return
			}
			break
		case http.MethodPost:
			if r.Header.Get("Content-Type") != "application/json" {
				f5Error(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not read request")
				return
			}
			var newProfile models.ClientSSLProfile
			err = json.Unmarshal(bodyBytes, &newProfile)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid post request")
				return
			}

			validate := validator.New(validator.WithRequiredStructEnabled())

			err = validate.Struct(newProfile)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid request")
				return
			}

			err = validateCert(newProfile.Cert, version)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid cert: %s", err.Error())
				return
			}

			foundProfile := findProfile(newProfile.Partition, newProfile.Name)
			if foundProfile != nil {
				f5Error(w, http.StatusBadRequest, "profile already exists")
				return
			}

			log.Println(fmt.Sprintf("DEBUG: Added %s profile", newProfile.Name))

			cache.GlobalCache.ClientSSLProfiles = append(cache.GlobalCache.ClientSSLProfiles, &newProfile)

			respBytes, err := json.Marshal(newProfile)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not marshal response")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not write response")
				return
			}

			break
		default:
			f5Error(w, http.StatusNotFound, "invalid method")
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

func (h ClientSSLHandler) Handler() IControlHandlerFunc {
	return authenticatedIControlRequestMiddleware(func(w http.ResponseWriter, r *http.Request, version int) {
		partition, profileName, err := parsePath(r.PathValue("profile"))

		if err != nil {
			f5Error(w, http.StatusBadRequest, err.Error())
			return
		}

		foundProfile := findProfile(partition, profileName)

		if foundProfile == nil {
			f5Error(w, http.StatusNotFound, "could not find profile")
			return
		}

		switch r.Method {
		case http.MethodGet:
			asMap, err := filterFields(*foundProfile, r.URL.Query().Get("$select"))
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not select field")
				return
			}

			respBytes, err := json.Marshal(asMap)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not marshal")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not write response")
				return
			}
			break
		case http.MethodPatch:
			if r.Header.Get("Content-Type") != "application/json" {
				f5Error(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not read request")
				return
			}
			var patchRequest PatchClientSSLProfile
			err = json.Unmarshal(bodyBytes, &patchRequest)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid patch request")
				return
			}

			validate := validator.New(validator.WithRequiredStructEnabled())

			err = validate.Struct(patchRequest)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid request")
				return
			}

			err = validateCert(patchRequest.Cert, version)
			if err != nil {
				f5Error(w, http.StatusBadRequest, "invalid cert: %s", err.Error())
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
				f5Error(w, http.StatusInternalServerError, "could not marshal response")
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, http.StatusInternalServerError, "could not write response")
				return
			}
			break
		default:
			f5Error(w, http.StatusNotFound, "invalid method")
			return
		}

	})
}

type PatchClientSSLProfile struct {
	DefaultsFrom string `json:"defaultsFrom" validate:"required"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
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
	certBytes, err := cache.GlobalCache.Fs.ReadFile(filepath.Join("certs", path))
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
