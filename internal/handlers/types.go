package handlers

import (
	"net/http"
)

type F5Handler interface {
	Route() string
	Handler() http.HandlerFunc
}
