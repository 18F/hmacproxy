package main

import (
	"flag"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
)

func newHandler(flags *flag.FlagSet, opts *HmacProxyOpts,
	argv []string) (handler http.Handler, description string) {
	if err := flags.Parse(argv); err != nil {
		panic("error parsing argv: " + err.Error())
	}

	// The full command-line program requires that -port be greater than
	// zero, but the test servers will pick ports dynamically. To avoid
	// having useless -port arguments in the test, we'll add a fake
	// argument here.
	opts.Port = 1
	if err := opts.Validate(); err != nil {
		panic("error parsing options: " + err.Error())
	}
	return NewHttpProxyHandler(opts)
}

type proxiedServer struct {
	http.Handler
}

func (ps proxiedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Success!"))
}

var _ = Describe("HmacProxy Handlers", func() {
	var (
		localOpts, upstreamOpts   *HmacProxyOpts
		localFlags, upstreamFlags *flag.FlagSet
	)

	BeforeEach(func() {
		localFlags = flag.NewFlagSet(
			"HmacProxy Handlers (local)", flag.ContinueOnError)
		localOpts = RegisterCommandLineOptions(localFlags)
		upstreamFlags = flag.NewFlagSet(
			"HmacProxy Handlers (upstream)", flag.ContinueOnError)
		upstreamOpts = RegisterCommandLineOptions(upstreamFlags)
	})

	localServer := func(argv []string) (*httptest.Server, string) {
		handler, desc := newHandler(localFlags, localOpts, argv)
		return httptest.NewServer(handler), desc
	}

	upstreamServer := func(argv []string) (*httptest.Server, string) {
		handler, desc := newHandler(upstreamFlags, upstreamOpts, argv)
		return httptest.NewServer(handler), desc
	}

	Context("sending requests to an auth-only upstream", func() {
		It("should succeed when the configurations match", func() {
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=Content-Type",
				"-auth",
			})
			Expect(upstreamDesc).To(Equal("responding " +
				"Accepted/Unauthorized for auth queries"))

			local, localDesc := localServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=content-type",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(local.URL)
			defer response.Body.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(
				Equal(http.StatusAccepted))
		})

		It("should fail when the configurations don't match", func() {
			// In this case, we'll switch the order of the
			// headers.
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=Content-Type",
				"-auth",
			})
			Expect(upstreamDesc).To(Equal("responding " +
				"Accepted/Unauthorized for auth queries"))

			local, localDesc := localServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(local.URL)
			defer response.Body.Close()
			body, err := ioutil.ReadAll(response.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(
				Equal(http.StatusUnauthorized))
			Expect(string(body)).To(Equal("unauthorized request\n"))
		})
	})

	Context("sending requests to a file serving upstream", func() {
		It("should succeed when the configurations match", func() {
			cwd, _ := os.Getwd()
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=Content-Type",
				"-auth",
				"-file-root=" + cwd,
			})
			Expect(upstreamDesc).To(Equal("serving files from " +
				cwd + " for authenticated requests"))

			// Notice that we can send the server any supported
			// digest.
			local, localDesc := localServer([]string{
				"-digest=md5",
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=content-type",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(
				local.URL + "/handlers_test.go")
			defer response.Body.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusOK))
		})

		It("should fail when the configurations don't match", func() {
			cwd, _ := os.Getwd()
			// This time, let's change the password.
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=bazquux",
				"-sign-header=Test-Signature",
				"-headers=Content-Type",
				"-auth",
				"-file-root=" + cwd,
			})
			Expect(upstreamDesc).To(Equal("serving files from " +
				cwd + " for authenticated requests"))

			local, localDesc := localServer([]string{
				"-digest=md5",
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=content-type",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(
				local.URL + "/handlers_test.go")
			defer response.Body.Close()
			body, err := ioutil.ReadAll(response.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(
				Equal(http.StatusUnauthorized))
			Expect(string(body)).To(Equal("unauthorized request\n"))
		})
	})

	Context("sending requests to a proxying upstream", func() {
		It("should succeed when the configurations match", func() {
			proxied := httptest.NewServer(proxiedServer{})
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=Content-Type",
				"-auth",
				"-upstream=" + proxied.URL,
			})
			Expect(upstreamDesc).To(Equal("proxying " +
				"authenticated requests to: " + proxied.URL))

			local, localDesc := localServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=content-type",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(local.URL)
			defer response.Body.Close()
			Expect(err).NotTo(HaveOccurred())
			body, err := ioutil.ReadAll(response.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusOK))
			Expect(string(body)).To(Equal("Success!"))
		})

		It("should fail when the configurations don't match", func() {
			proxied := httptest.NewServer(proxiedServer{})
			// This time we'll change the sign-header.
			upstream, upstreamDesc := upstreamServer([]string{
				"-secret=foobar",
				"-sign-header=X-Test-Signature",
				"-headers=Content-Type",
				"-auth",
				"-upstream=" + proxied.URL,
			})
			Expect(upstreamDesc).To(Equal("proxying " +
				"authenticated requests to: " + proxied.URL))

			local, localDesc := localServer([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-headers=content-type",
				"-upstream=" + upstream.URL,
			})
			Expect(localDesc).To(Equal("proxying signed " +
				"requests to: " + upstream.URL))

			response, err := http.Get(local.URL)
			defer response.Body.Close()
			Expect(err).NotTo(HaveOccurred())
			body, err := ioutil.ReadAll(response.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(
				Equal(http.StatusUnauthorized))
			Expect(string(body)).To(Equal("unauthorized request\n"))
		})
	})
})
