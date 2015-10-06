package main

import (
	"crypto"
	"errors"
	"flag"
	"github.com/18F/hmacauth"
	"net/url"
	"os"
	"strings"
)

// HmacProxyOpts contains the parameters needed to determine which
// authentication handler to launch and to configure it properly.
type HmacProxyOpts struct {
	Port       int
	Auth       bool
	Digest     HmacProxyDigest
	Secret     string
	SignHeader string
	Headers    HmacProxyHeaders
	Upstream   HmacProxyURL
	FileRoot   string
	SslCert    string
	SslKey     string
	Mode       HmacProxyMode
}

// RegisterCommandLineOptions configures flags to fill in the fields of a new
// HmacProxyOpts object based on command line options.
func RegisterCommandLineOptions(flags *flag.FlagSet) (opts *HmacProxyOpts) {
	opts = &HmacProxyOpts{}
	flags.IntVar(&opts.Port, "port", 0,
		"Port on which to listen for requests")
	flags.BoolVar(&opts.Auth, "auth", false,
		"Authenticate requests rather than signing them")
	flags.StringVar(&opts.Digest.Name, "digest", "sha1",
		"Hash algorithm to use when signing requests")
	flags.StringVar(&opts.Secret, "secret", "",
		"Secret key")
	flags.StringVar(&opts.SignHeader, "sign-header", "",
		"Header containing request signature")
	flags.Var(&opts.Headers, "headers",
		"Headers to factor into the signature, comma-separated")
	flags.StringVar(&opts.Upstream.Raw, "upstream", "",
		"Signed/authenticated requests are proxied to this server")
	flags.StringVar(&opts.FileRoot, "file-root", "",
		"Root of file system from which to serve documents")
	flags.StringVar(&opts.SslCert, "ssl-cert", "",
		"Path to the server's SSL certificate")
	flags.StringVar(&opts.SslKey, "ssl-key", "",
		"Path to the key for -ssl-cert")
	return
}

// Validate ensures that the HmacProxyOpts configuration is correct and parses
// some of the values into a useable format. It also sets the Mode member that
// determines which proxy handler to launch. Collects as many error messages
// as possible and returns them as a single string via the err return value.
func (opts *HmacProxyOpts) Validate() (err error) {
	var msgs []string
	msgs = validateMode(opts, msgs)
	msgs = validatePort(opts, msgs)
	msgs = validateAuthParams(opts, msgs)
	msgs = validateUpstream(opts, msgs)
	msgs = validateFileRoot(opts, msgs)
	msgs = validateSsl(opts, msgs)

	if len(msgs) != 0 {
		err = errors.New("Invalid options:\n  " +
			strings.Join(msgs, "\n  "))
	}
	return
}

// HmacProxyHeaders defines a []string that can be used with
// flag.FlagSet.Var() to parse the comma-separated command line values into
// the slice.
type HmacProxyHeaders []string

// String returns a string representation of HmacProxyHeaders.
func (hph *HmacProxyHeaders) String() string {
	return strings.Join(*hph, ",")
}

// Set parses comma-separated values from the input string into the
// HmacProxyHeaders instance.
func (hph *HmacProxyHeaders) Set(s string) error {
	*hph = strings.Split(s, ",")
	return nil
}

// HmacProxyMode specifies the type of handler to return from
// NewHTTPProxyHandler.
type HmacProxyMode int

const (
	// HandlerSignAndProxy for a handler that signs requests before
	// proxying them to an upstream server
	HandlerSignAndProxy HmacProxyMode = iota

	// HandlerAuthAndProxy for a handler that authenticates requests
	// before proxying them to an upstream server
	HandlerAuthAndProxy

	// HandlerAuthForFiles for a handler that will authenticate requests
	// before returning local file system content from -file-root
	HandlerAuthForFiles

	// HandlerAuthOnly for a handler that returns 202 or 401 HTTP status
	// codes after authenticating a request (or not)
	HandlerAuthOnly
)

func validateMode(opts *HmacProxyOpts, msgs []string) []string {
	upstreamDefined := opts.Upstream.Raw != ""
	fileRootDefined := opts.FileRoot != ""

	if !(upstreamDefined || fileRootDefined || opts.Auth) {
		msgs = append(msgs, "neither -upstream, -file-root, "+
			"nor -auth specified")
	} else if upstreamDefined && fileRootDefined {
		msgs = append(msgs, "both -upstream and -file-root specified")
	}
	if fileRootDefined && !opts.Auth {
		msgs = append(msgs, "-auth must be specified with -file-root")
	}

	if !opts.Auth {
		opts.Mode = HandlerSignAndProxy
	} else if upstreamDefined {
		opts.Mode = HandlerAuthAndProxy
	} else if fileRootDefined {
		opts.Mode = HandlerAuthForFiles
	} else {
		opts.Mode = HandlerAuthOnly
	}
	return msgs
}

func validatePort(opts *HmacProxyOpts, msgs []string) []string {
	if opts.Port <= 0 {
		msgs = append(msgs, "port must be specified and "+
			"greater than zero")
	}
	return msgs
}

// HmacProxyDigest is a mapping from a hash algorithm name to its ID in the
// crypto.Hash package, and vice-versa.
type HmacProxyDigest struct {
	Name string
	ID   crypto.Hash
}

func validateAuthParams(opts *HmacProxyOpts, msgs []string) []string {
	var err error
	opts.Digest.ID, err = hmacauth.DigestNameToCryptoHash(opts.Digest.Name)
	if err != nil {
		msgs = append(msgs, "unsupported digest: "+opts.Digest.Name)
	}
	if opts.Secret == "" {
		msgs = append(msgs, "no secret specified")
	}
	if opts.SignHeader == "" {
		msgs = append(msgs, "no signature header specified")
	}
	return msgs
}

// HmacProxyURL contains a raw URL string from the command line as well as its
// parsed representation.
type HmacProxyURL struct {
	Raw string
	URL *url.URL
}

func validateUpstream(opts *HmacProxyOpts, msgs []string) []string {
	if opts.Upstream.Raw == "" {
		return msgs
	}

	var err error
	if opts.Upstream.URL, err = url.Parse(opts.Upstream.Raw); err != nil {
		msgs = append(msgs, "upstream URL failed to parse"+err.Error())
	}
	scheme := opts.Upstream.URL.Scheme
	if scheme == "" {
		msgs = append(msgs, "upstream scheme not specified")
	} else if !(scheme == "http" || scheme == "https") {
		msgs = append(msgs, "invalid upstream scheme: "+scheme)
	}
	if host := opts.Upstream.URL.Host; host == "" {
		msgs = append(msgs, "upstream host not specified")
	}
	if path := opts.Upstream.URL.RequestURI(); path != "/" {
		msgs = append(msgs, "upstream path must be \"/\", not "+path)
	}
	return msgs
}

func checkExistenceAndPermission(path, optionName, dirOrFile string,
	msgs []string) []string {
	if dirOrFile != "dir" && dirOrFile != "file" {
		panic("invalid dirOrFile parameter: " + dirOrFile)
	}

	if info, err := os.Stat(path); os.IsNotExist(err) {
		msgs = append(msgs, optionName+" does not exist: "+path)
	} else if os.IsPermission(err) {
		msgs = append(msgs, optionName+" permission is denied: "+path)
	} else if dirOrFile == "dir" && !info.IsDir() {
		msgs = append(msgs, optionName+" is not a directory: "+path)
	} else if dirOrFile == "file" && !info.Mode().IsRegular() {
		msgs = append(msgs, optionName+" is not a regular file: "+path)
	}
	return msgs
}

func validateFileRoot(opts *HmacProxyOpts, msgs []string) []string {
	if opts.FileRoot == "" {
		return msgs
	}
	return checkExistenceAndPermission(
		opts.FileRoot, "file-root", "dir", msgs)
}

func validateSsl(opts *HmacProxyOpts, msgs []string) []string {
	certSpecified := opts.SslCert != ""
	keySpecified := opts.SslKey != ""
	if !(certSpecified || keySpecified) {
		return msgs
	} else if !(certSpecified && keySpecified) {
		msgs = append(msgs, "ssl-cert and ssl-key must both be "+
			"specified, or neither must be")
	}

	if certSpecified {
		msgs = checkExistenceAndPermission(
			opts.SslCert, "ssl-cert", "file", msgs)
	}
	if keySpecified {
		msgs = checkExistenceAndPermission(
			opts.SslKey, "ssl-key", "file", msgs)
	}
	return msgs
}
