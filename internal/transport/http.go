package transport

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type httpReader struct {
	URL     string
	Timeout time.Duration
}

// PatchTLSConfig allows patching passed tls.Config instance values based
// on Alertmanager instance TLS configuration
func PatchTLSConfig(tlsConfig *tls.Config, patchCfg TLSConfig) error {
	if patchCfg.CertPath != "" && patchCfg.KeyPath != "" {
		log.Debugf("Loading TLS cert '%s' and key '%s'", patchCfg.CertPath, patchCfg.KeyPath)
		cert, err := tls.LoadX509KeyPair(patchCfg.CertPath, patchCfg.KeyPath)
		if err != nil {
			log.Debugf("Failed to load cert and key: %s", err)
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if patchCfg.CAPath != "" {
		log.Debugf("Loading TLS CA cert '%s'", patchCfg.CAPath)
		caCert, err := ioutil.ReadFile(patchCfg.CAPath)
		if err != nil {
			log.Debugf("Failed to load CA cert: %s", err)
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	tlsConfig.BuildNameToCertificate()
	return nil
}

func newHTTPReader(url string, timeout time.Duration, transport http.RoundTripper) (io.ReadCloser, error) {
	hr := httpReader{URL: url, Timeout: timeout}

	log.Infof("GET %s timeout=%s", hr.URL, hr.Timeout)

	c := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", hr.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept-Encoding", "gzip")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Request to Alertmanager failed with %s", resp.Status)
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode gzipped content: %s", err.Error())
		}
	default:
		reader = resp.Body
	}
	return reader, nil
}
