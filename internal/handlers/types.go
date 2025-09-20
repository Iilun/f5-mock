package handlers

import (
	"github.com/iilun/f5-mock/internal/log"
	"net/http"
)

// F5Handler is the interface to implement for all handlers
type F5Handler interface {
	Route() string
	Handler() http.HandlerFunc
}

type F5HandlerWrapper struct {
	wrapped F5Handler
	logger  log.Logger
}

func (w F5HandlerWrapper) Route() string {
	return w.wrapped.Route()
}

func (w F5HandlerWrapper) Handler() http.HandlerFunc {
	return loggingMiddleware(w.logger, applyVersionMiddleware(w.wrapped.Handler()))
}

func RegisterHandler(h F5Handler, log log.Logger) {
	// Wrap to apply all base middlewares
	wrapped := F5HandlerWrapper{h, log}

	http.HandleFunc(wrapped.Route(), wrapped.Handler())
}
