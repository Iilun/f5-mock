package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func checkContentType(r *http.Request, ct string) error {
	if r.Header.Get("Content-Type") != ct {
		return fmt.Errorf("invalid content-type: expected %s", ct)
	}
	return nil
}

func parsePath(path string) (string, string, error) {
	splitProfile := strings.Split(path, "~")

	if os.Getenv("F5_DEFAULT_PARTITION") != "" && len(splitProfile) == 1 {
		return os.Getenv("F5_DEFAULT_PARTITION"), path, nil
	}

	if len(splitProfile) != 3 {
		return "", "", errors.New("invalid path")
	}

	return splitProfile[1], splitProfile[2], nil
}
