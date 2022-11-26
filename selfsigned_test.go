package selfsigned

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	assert := require.New(t)

	result, err := GenerateCert(
		Hosts([]string{"127.0.0.1", "localhost"}),
		RSABits(4096),
		ValidFor(365*24*time.Hour),
	)
	assert.NoError(err)

	log.Println("fingerprints", result.Fingerprint)
	assert.NotEmpty(result.Fingerprint)

	cert, err := tls.X509KeyPair(result.PublicCert, result.PrivateKey)
	assert.NoError(err)

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	res, err := client.Get(ts.URL)
	assert.NoError(err)

	greeting, err := io.ReadAll(res.Body)
	res.Body.Close()
	assert.NoError(err)
	assert.Equal("Hello, client\n", string(greeting))
}
