package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

func main() {
	opts := RegisterCommandLineOptions(flag.CommandLine)
	flag.Parse()
	if err := opts.Validate(); err != nil {
		log.Fatal(err)
	}

	address := ":" + strconv.Itoa(opts.Port)
	handler, description := NewHTTPProxyHandler(opts)
	server := &http.Server{Addr: address, Handler: handler}
	fmt.Printf("port %d: %s\n", opts.Port, description)

	var err error
	if opts.SslCert != "" {
		err = server.ListenAndServeTLS(opts.SslCert, opts.SslKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}
