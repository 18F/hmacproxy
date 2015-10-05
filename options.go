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

type HmacProxyOpts struct {
	Port       int
	Auth       bool
	Digest     HmacProxyDigest
	Secret     string
	SignHeader string
	Headers    HmacProxyHeaders
	Upstream   HmacProxyUrl
	FileRoot   string
	SslCert    string
	SslKey     string
	Mode       HmacProxyMode
}

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

func (opts *HmacProxyOpts) Validate() (err error) {
	msgs := make([]string, 0)
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

type HmacProxyHeaders []string

func (hph *HmacProxyHeaders) String() string {
	return strings.Join(*hph, ",")
}

func (hph *HmacProxyHeaders) Set(s string) error {
	*hph = strings.Split(s, ",")
	return nil
}

type HmacProxyMode int

const (
	SIGN_AND_PROXY HmacProxyMode = iota
	AUTH_AND_PROXY
	AUTH_FOR_FILES
	AUTH_ONLY
)

func validateMode(opts *HmacProxyOpts, msgs []string) []string {
	upstreamDefined := opts.Upstream.Raw != ""
	fileRootDefined := opts.FileRoot != ""

	if upstreamDefined && fileRootDefined {
		msgs = append(msgs, "both -upstream and -file-root specified")
	} else if !(upstreamDefined || fileRootDefined || opts.Auth) {
		msgs = append(msgs,
			"neither -upstream, -file-root, nor -auth specified")
	}
	if fileRootDefined && !opts.Auth {
		msgs = append(msgs, "-auth must be specified with -file-root")
	}

	if opts.Auth {
		if upstreamDefined {
			opts.Mode = AUTH_AND_PROXY
		} else if fileRootDefined {
			opts.Mode = AUTH_FOR_FILES
		} else {
			opts.Mode = AUTH_ONLY
		}
	} else {
		opts.Mode = SIGN_AND_PROXY
	}
	return msgs
}

func validatePort(opts *HmacProxyOpts, msgs []string) []string {
	if opts.Port <= 0 {
		msgs = append(msgs, "port must be specified and " +
			"greater than zero")
	}
	return msgs
}

type HmacProxyDigest struct {
	Name string
	Id   crypto.Hash
}

func validateAuthParams(opts *HmacProxyOpts, msgs []string) []string {
	var err error
	opts.Digest.Id, err = hmacauth.DigestNameToCryptoHash(opts.Digest.Name)
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

type HmacProxyUrl struct {
	Raw string
	Url *url.URL
}

func validateUpstream(opts *HmacProxyOpts, msgs []string) []string {
	if opts.Upstream.Raw == "" {
		return msgs
	}

	var err error
	if opts.Upstream.Url, err = url.Parse(opts.Upstream.Raw); err != nil {
		msgs = append(msgs, "upstream URL failed to parse"+err.Error())
	}
	scheme := opts.Upstream.Url.Scheme
	if scheme == "" {
		msgs = append(msgs, "upstream scheme not specified")
	} else if !(scheme == "http" || scheme == "https") {
		msgs = append(msgs, "invalid upstream scheme: "+scheme)
	}
	if host := opts.Upstream.Url.Host; host == "" {
		msgs = append(msgs, "upstream host not specified")
	}
	if path := opts.Upstream.Url.RequestURI(); path != "/" {
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
