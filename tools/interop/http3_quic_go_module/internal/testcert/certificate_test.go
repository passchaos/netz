package testcert

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLocalhostUsesServerLeafAndSeparateCA(t *testing.T) {
	certificate, caPEM, err := Localhost()
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 2 {
		t.Fatalf("certificate chain length = %d, want 2", len(certificate.Certificate))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid CA PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatalf("invalid server leaf usage: is_ca=%t key_usage=%v", leaf.IsCA, leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("invalid server leaf EKU: %v", leaf.ExtKeyUsage)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("verify leaf hostname: %v", err)
	}
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("invalid CA usage: is_ca=%t key_usage=%v", ca.IsCA, ca.KeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parsed)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: "localhost",
	}); err != nil {
		t.Fatalf("verify certificate chain: %v", err)
	}
}
