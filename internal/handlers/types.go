package handlers

import (
	"net/http"
)

type IControlHandlerFunc func(w http.ResponseWriter, r *http.Request, version int)

type F5Handler interface {
	Route() string
	Handler() http.HandlerFunc
}

type IControlHandler interface {
	Route() string
	Handler() IControlHandlerFunc
}

type iControlHandlerWrapper struct {
	IControlHandler
}

func (i iControlHandlerWrapper) Handler() http.HandlerFunc {
	return iControlMiddleWare(i.IControlHandler.Handler())
}

func WrapIControl(i IControlHandler) F5Handler {
	return iControlHandlerWrapper{i}
}
