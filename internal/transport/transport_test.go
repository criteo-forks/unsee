package transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/unsee/internal/mock"
	"github.com/cloudflare/unsee/internal/transport"

	log "github.com/sirupsen/logrus"
)

type httpTransportTest struct {
	useTLS    bool
	timeout   time.Duration
	tlsConfig transport.TLSConfig
	failed    bool
}

var httpTransportTests = []httpTransportTest{
	httpTransportTest{},
	httpTransportTest{
		useTLS: true,
	},
	httpTransportTest{
		useTLS: true,
		tlsConfig: transport.TLSConfig{
			CAPath: "/non-existing-path/ca.pem",
		},
		failed: true,
	},
	httpTransportTest{
		useTLS: true,
		tlsConfig: transport.TLSConfig{
			CertPath: "/non-existing-path/cert.pem",
			KeyPath:  "/non-existing-path/key.pem",
		},
		failed: true,
	},
}

type fileTransportTest struct {
	uri     string
	failed  bool
	timeout time.Duration
}

var fileTransportTests = []fileTransportTest{
	fileTransportTest{
		uri: fmt.Sprintf("file://%s", mock.GetAbsoluteMockPath("status", mock.ListAllMocks()[0])),
	},
	fileTransportTest{
		uri:    "file:///non-existing-file.abcdef",
		failed: true,
	},
	fileTransportTest{
		uri:    "file://transport.go",
		failed: true,
	},
}

type mockStatus struct {
	status  string
	integer int
	yes     bool
	no      bool
}

func TestHTTPReader(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"status": "success", "integer": 123, "yes": true, "no": false}`)
	}
	plainTS := httptest.NewServer(http.HandlerFunc(handler))
	defer plainTS.Close()

	tlsTS := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer tlsTS.Close()
	caPool := x509.NewCertPool()
	caPool.AddCert(tlsTS.Certificate())

	for _, testCase := range httpTransportTests {
		var uri string
		if testCase.useTLS {
			uri = tlsTS.URL
		} else {
			uri = plainTS.URL
		}

		tlsConfig := tls.Config{RootCAs: caPool}
		err := transport.PatchTLSConfig(&tlsConfig, testCase.tlsConfig)
		if (err != nil) != testCase.failed {
			t.Errorf("[%v] Unexpected PatchTLSConfig() result, failure=%v, expected=%v, error: %s", testCase, (err != nil), testCase.failed, err)
		}

		if err == nil {
			r := mockStatus{}
			err = transport.ReadJSON(uri, testCase.timeout, &tlsConfig, &r)
			if (err != nil) != testCase.failed {
				t.Errorf("[%v] Unexpected ReadJSON() result, failure=%v, expected=%v, error: %s", testCase, (err != nil), testCase.failed, err)
			}
		}
	}
}

func TestFileReader(t *testing.T) {
	log.SetLevel(log.PanicLevel)
	for _, testCase := range fileTransportTests {
		r := mockStatus{}
		err := transport.ReadJSON(testCase.uri, testCase.timeout, nil, &r)
		if (err != nil) != testCase.failed {
			t.Errorf("[%v] Unexpected result, failure=%v, expected=%v, error: %s", testCase, (err != nil), testCase.failed, err)
		}
	}
}
