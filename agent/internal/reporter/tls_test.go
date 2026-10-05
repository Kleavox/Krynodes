package reporter

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectionsToKrynodesRefuseTLS12(t *testing.T) {
	for _, newest := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		server.TLS = &tls.Config{MaxVersion: newest}
		server.StartTLS()
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		config := TLSConfig()
		config.RootCAs = pool
		response, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: config}}).Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		server.Close()
		if (err == nil) != (newest == tls.VersionTLS13) {
			t.Fatalf("server up to %x: %v", newest, err)
		}
	}
	transport, ok := New("https://kry.example", "token", "0.4.1").httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("reports and enrollment must need TLS 1.3")
	}
}
