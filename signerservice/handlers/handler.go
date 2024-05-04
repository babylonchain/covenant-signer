package handlers

import (
	"context"
	s "github.com/babylonchain/covenant-signer/signerapp"
	"net/http"
)

type Handler struct {
	s *s.SignerApp
}

type Result struct {
	Data   interface{}
	Status int
}

type PublicResponse[T any] struct {
	Data T `json:"data"`
}

func NewResult[T any](data T) *Result {
	res := &PublicResponse[T]{Data: data}
	return &Result{Data: res, Status: http.StatusOK}
}

func NewHandler(
	_ context.Context, s *s.SignerApp,
) (*Handler, error) {
	return &Handler{
		s: s,
	}, nil
}
