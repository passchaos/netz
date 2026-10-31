// HTTP3 digest peer uses pinned quic-go and Go's independent SHA/gzip codecs.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/quic-go/quic-go"
	"log"
	"netz-quic-go-interop/internal/testcert"
	"os"
	"time"
)

func main() {
	mode := flag.String("mode", "server", "server, client or identity")
	address := flag.String("addr", "127.0.0.1:0", "UDP address")
	version := flag.Int("version", 1, "QUIC version 1 or 2")
	ca := flag.String("ca", "", "CA PEM path")
	cert := flag.String("cert", "", "leaf/chain PEM path")
	key := flag.String("key", "", "PKCS8 key PEM path")
	flag.Parse()
	if *version != 1 && *version != 2 {
		log.Fatal("invalid QUIC version")
	}
	var err error
	switch *mode {
	case "identity":
		err = identity(*ca, *cert, *key)
	case "server":
		err = server(*address, *ca, *cert, *key, *version)
	case "client":
		err = client(*address, *ca, *version)
	default:
		err = errors.New("invalid mode")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func identity(caPath, certPath, keyPath string) error {
	certificate, ca, err := testcert.Localhost()
	if err != nil {
		return err
	}
	var chain []byte
	for _, der := range certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return err
	}
	for path, content := range map[string][]byte{caPath: ca, certPath: chain, keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func config(version int) *quic.Config {
	wire := quic.Version1
	if version == 2 {
		wire = quic.Version2
	}
	return &quic.Config{Versions: []quic.Version{wire}, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 10 * time.Second,
		InitialStreamReceiveWindow: 2048, MaxStreamReceiveWindow: 2048,
		InitialConnectionReceiveWindow: 8192, MaxConnectionReceiveWindow: 8192}
}

func summary(role string, version int, connections uint32) {
	data, _ := json.Marshal(map[string]any{"role": role, "version": version, "connections": connections, "requests": len(paths), "paths": paths,
		"tls": "TLSv1.3", "alpn": "h3", "generated_verified": true, "complete_request_bytes": len(generated), "corruption_detected": role == "quic-go-client", "injected_corruption": role == "quic-go-server", "stream_window": 2048})
	fmt.Printf("RESULT %s\n", data)
}
