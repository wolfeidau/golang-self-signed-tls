# golang-self-signed-tls

This library provides a self signed certificate in the formats required to setup a TLS listener in Go without needing to certificate files in your docker container. It ensures we have safe encrypted in flight connections this library generates new certificates each time it is called, reducing the chance of leaked private keys.

# Why?

Putting certificate files in your docker container are a security risk. If the container is leaked at some point in the future the private key maybe used to retrospectively decrypt data.

# Usage

```go
	result, err := GenerateCert(
		Hosts([]string{"127.0.0.1", "localhost"}),
		RSABits(4096),
		ValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("fingerprint", result.Fingerprint)

	cert, err := tls.X509KeyPair(result.PublicCert, result.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
```

# License

This code was authored by [Mark Wolfe](https://www.wolfe.id.au) and licensed under the [Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0).
