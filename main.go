package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
)

func main() {
	opts := RegisterCommandLineOptions(flag.CommandLine)
	flag.Parse()
	if err := opts.Validate(); err != nil {
		log.Fatal(err)
	}

	address := "localhost:" + strconv.Itoa(opts.Port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("listening on " + address + " failed: " + err.Error())
	}
	defer listener.Close()
	address = listener.Addr().String()

	handler, description := NewHttpProxyHandler(opts)
	server := &http.Server{Addr: address, Handler: handler}
	fmt.Printf("%s: %s\n", address, description)

	if opts.SslCert != "" {
		http.ListenAndServeTLS(address, opts.SslCert, opts.SslKey, handler)
	} else {
		server.Serve(listener)
	}
}
