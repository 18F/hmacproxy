package main

import (
	"github.com/18F/hmacauth"
	"log"
	"net/http"
	"net/http/httputil"
)

func NewHttpProxyHandler(opts *HmacProxyOpts) (
	handler http.Handler, description string) {
	auth := hmacauth.NewHmacAuth(opts.Digest.Id,
		[]byte(opts.Secret), opts.SignHeader, opts.Headers)

	switch opts.Mode {
	case SIGN_AND_PROXY:
		return signAndProxyHandler(auth, &opts.Upstream)
	case AUTH_AND_PROXY:
		return authAndProxyHandler(auth, &opts.Upstream)
	case AUTH_FOR_FILES:
		return authForFilesHandler(auth, opts.FileRoot)
	case AUTH_ONLY:
		return authenticationOnlyHandler(auth)
	}
	log.Fatalf("unknown mode: %d\n", opts.Mode)
	return
}

type signingHandler struct {
	auth    *hmacauth.HmacAuth
	handler http.Handler
}

func (h signingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.auth.SignRequest(r)
	h.handler.ServeHTTP(w, r)
}

func signAndProxyHandler(auth *hmacauth.HmacAuth, upstream *HmacProxyUrl) (
	handler http.Handler, description string) {
	description = "proxying signed requests to: " + upstream.Raw
	proxy := httputil.NewSingleHostReverseProxy(upstream.Url)
	handler = signingHandler{auth, proxy}
	return
}

type authHandler struct {
	auth    *hmacauth.HmacAuth
	handler http.Handler
}

func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result, _, _ := h.auth.ValidateRequest(r)
	if result != hmacauth.MATCH {
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	} else {
		h.handler.ServeHTTP(w, r)
	}
}

func authAndProxyHandler(auth *hmacauth.HmacAuth, upstream *HmacProxyUrl) (
	handler http.Handler, description string) {
	description = "proxying authenticated requests to: " + upstream.Raw
	proxy := httputil.NewSingleHostReverseProxy(upstream.Url)
	handler = authHandler{auth, proxy}
	return
}

func authForFilesHandler(auth *hmacauth.HmacAuth, fileRoot string) (
	handler http.Handler, description string) {
	description = "serving files from " + fileRoot +
		" for authenticated requests"
	fileServer := http.FileServer(http.Dir(fileRoot))
	handler = authHandler{auth, fileServer}
	return
}

type authOnlyHandler struct {
	auth *hmacauth.HmacAuth
}

func (h authOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result, _, _ := h.auth.ValidateRequest(r)
	if result != hmacauth.MATCH {
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

func authenticationOnlyHandler(auth *hmacauth.HmacAuth) (
	handler http.Handler, description string) {
	description = "responding Accepted/Unauthorized for auth queries"
	handler = authOnlyHandler{auth}
	return
}
