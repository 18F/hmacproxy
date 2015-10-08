# hmacproxy HMAC authentication proxy server

Proxy server that signs and authenticates HTTP requests using an HMAC
signature; uses the [github.com/18F/hmacauth Go package](https://github.com/18F/hmacauth).

[![Build Status](https://travis-ci.org/18F/hmacproxy.svg?branch=master)](https://travis-ci.org/18F/hmacproxy)

[![Coverage Status](https://coveralls.io/repos/18F/hmacproxy/badge.svg?branch=master&service=github)](https://coveralls.io/github/18F/hmacproxy?branch=master)

## Installation

For now, install from source:

```sh
$ go get github.com/18F/hmacproxy
```

## Testing out locally

The following will authenticate local requests and return a status of 202 if
everything works. Change the values for `-secret`, `-sign-header`, and
`-headers` to simulate authentication failures.

In the first shell:

```sh
$ hmacproxy -port 8081 -secret "foobar" -sign-header "X-Signature" -auth

127.0.0.1:8081: responding Accepted/Unauthorized for auth queries
```

In the second shell:

```sh
$ hmacproxy -port 8080 -secret "foobar" -sign-header "X-Signature" \
  -upstream http://localhost:8081/

127.0.0.1:8080: proxying signed requests to: http://localhost:8081/
```

In the third shell:

```sh
$ curl -i localhost:8080/18F/hmacproxy

HTTP/1.1 202 Accepted
Content-Length: 0
Content-Type: text/plain; charset=utf-8
Date: Mon, 05 Oct 2015 15:32:56 GMT
```

## Signing outgoing requests

```sh
$ hmacproxy -port 8080 -secret "foobar" -sign-header "X-Signature" \
  -upstream https://my-upstream.com/
```

## Validating incoming requests

All of the following require the `-auth` flag.

### Proxying to an upstream server

```sh
$ hmacproxy -port 8080 -secret "foobar" -sign-header "X-Signature" \
  -upstream https://my-upstream.com/ -auth
```

### Serving files directly

```sh
$ hmacproxy -port 8080 -secret "foobar" -sign-header "X-Signature" \
  -file-root /path/to/my/files -auth
```

### Returning an Accepted/Unauthorized status

This should be compatible with the [Nginx
`ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
by using an `auth_request` directive to proxy to the `hmacproxy`.

```sh
$ hmacproxy -port 8080 -secret "foobar" -sign-header "X-Signature" -auth
```

Then add configuration such as the following to your nginx instance, where:

- `PORT` is replaced with the port number of your service
- `myservice.com` is replaced with the virtual server name for your service
- `ssl/star.myservice.com.conf` contains the SSL configuration for your
  server.
- `http://127.0.0.1:8080` matches the address of the local `hmacproxy`
  instance from above
- The `X-Original-URI` header is added to the authentication request, defined
  using [the builtin `$request_uri` nginx
  variable](http://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri).

```
server {
  listen PORT ssl spdy;
  server_name  myservice.com;

  include ssl/star.myservice.com.conf;

  location = /auth {
    internal;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Original-URI $request_uri;
  }

  location / {
    auth_request /auth;
    ...
  }
}
```

## Accepting incoming requests over SSL

If you wish to expose the proxy endpoints directly to the public, rather than
via an Nginx proxy scheme, pass the `-ssl-cert` and `-ssl-key` options along
all other `-auth` parameters.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
