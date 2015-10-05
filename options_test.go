package main_test

import (
	"crypto"
	"flag"
	. "github.com/18F/hmacproxy"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
	"path/filepath"
	"strings"
)

func optionErrors(msgs []string) string {
	return "Invalid options:\n  " + strings.Join(msgs, "\n  ")
}

var _ = Describe("HmacProxyOpts", func() {
	var (
		opts  *HmacProxyOpts
		flags *flag.FlagSet
	)

	BeforeEach(func() {
		flags = flag.NewFlagSet(
			"HmacProxyOpts test", flag.ContinueOnError)
		opts = RegisterCommandLineOptions(flags)
	})

	Context("with a valid configuration", func() {
		It("should set sign-and-proxy mode using defaults", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=https://localhost:8080/",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.Secret).To(Equal("foobar"))
			Expect(opts.SignHeader).To(Equal("Test-Signature"))
			Expect(opts.Upstream.Raw).To(Equal(
				"https://localhost:8080/"))
			Expect(opts.Upstream.Url.String()).To(Equal(
				"https://localhost:8080/"))
			Expect(opts.Mode).To(Equal(SIGN_AND_PROXY))
		})

		It("should set auth-and-proxy mode using defaults", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=https://localhost:8080/",
				"-auth",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.Mode).To(Equal(AUTH_AND_PROXY))
		})

		It("should set auth-for-files mode using defaults", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-file-root=.",
				"-auth",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.FileRoot).To(Equal("."))
			Expect(opts.Mode).To(Equal(AUTH_FOR_FILES))
		})

		It("should set auth-only mode using defaults", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-auth",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.Mode).To(Equal(AUTH_ONLY))
		})

		It("should accept default overrides", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-auth",
				"-port=8080",
				"-digest=md5",
				"-headers=Content-Type,Date,Gap-Auth",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.Port).To(Equal(8080))
			Expect(opts.Digest.Name).To(Equal("md5"))
			Expect(opts.Digest.Id).To(Equal(crypto.MD5))
			Expect([]string(opts.Headers)).To(Equal([]string{
				"Content-Type", "Date", "Gap-Auth"}))
			Expect(opts.Mode).To(Equal(AUTH_ONLY))
		})

		It("should accept SSL options", func() {
			// Use filename as a file that's guaranteed to exist.
			cwd, _ := os.Getwd()
			filename := filepath.Join(cwd, "options_test.go")
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-auth",
				"-ssl-cert=" + filename,
				"-ssl-key=" + filename,
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts.SslCert).To(Equal(filename))
			Expect(opts.SslKey).To(Equal(filename))
			Expect(opts.Mode).To(Equal(AUTH_ONLY))
		})

	})

	Context("with an invalid configuration", func() {
		It("should report all errors for missing options", func() {
			err := flags.Parse([]string{})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"neither -upstream, -file-root, nor -auth " +
					"specified",
				"no secret specified",
				"no signature header specified",
			})))
		})

		It("should report all file root errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=http://localhost",
				"-file-root=bogus",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"both -upstream and -file-root specified",
				"-auth must be specified with -file-root",
				"file-root does not exist: bogus",
			})))
		})

		It("should report port and hash digest errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=http://localhost",
				"-port=-1",
				"-digest=unsupported",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"invalid port: -1",
				"unsupported digest: unsupported",
			})))
		})

		It("should report incomplete upstream spec errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=/",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"upstream scheme not specified",
				"upstream host not specified",
			})))
		})

		It("should report incorrect upstream spec errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=gopher://foo.com/bar/",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"invalid upstream scheme: gopher",
				"upstream path must be \"/\", not /bar/",
			})))
		})

		It("should report incorrect upstream spec errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=gopher://foo.com/bar/",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"invalid upstream scheme: gopher",
				"upstream path must be \"/\", not /bar/",
			})))
		})

		It("should report missing ssl-key option", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=https://localhost:8080/",
				"-ssl-cert=cert.pem",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"ssl-cert and ssl-key must both be " +
					"specified, or neither must be",
				"ssl-cert does not exist: cert.pem",
			})))
		})

		It("should report missing ssl-cert option", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=https://localhost:8080/",
				"-ssl-key=key.pem",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"ssl-cert and ssl-key must both be " +
					"specified, or neither must be",
				"ssl-key does not exist: key.pem",
			})))
		})

		It("should report missing ssl-cert and ssl-key errors", func() {
			err := flags.Parse([]string{
				"-secret=foobar",
				"-sign-header=Test-Signature",
				"-upstream=https://localhost:8080/",
				"-ssl-cert=cert.pem",
				"-ssl-key=key.pem",
			})
			Expect(err).NotTo(HaveOccurred())
			err = opts.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(optionErrors([]string{
				"ssl-cert does not exist: cert.pem",
				"ssl-key does not exist: key.pem",
			})))
		})
	})
})
