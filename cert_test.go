// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMkcert_FileNames(t *testing.T) {
	t.Run("a single host", func(t *testing.T) {
		m := &mkcert{}
		certFile, keyFile, p12File := m.fileNames([]string{"example.com"})
		if certFile != "./example.com.pem" {
			t.Errorf("should name the cert after the host, got %q", certFile)
		}
		if keyFile != "./example.com-key.pem" {
			t.Errorf("should suffix the key with -key, got %q", keyFile)
		}
		if p12File != "./example.com.p12" {
			t.Errorf("should give the p12 a .p12 extension, got %q", p12File)
		}
	})

	t.Run("multiple hosts get a plus count", func(t *testing.T) {
		// With more than one host mkcert appends +N where N is the number of
		// extra hosts. Three hosts means example.com+2.
		m := &mkcert{}
		certFile, _, _ := m.fileNames([]string{"example.com", "example.org", "localhost"})
		if certFile != "./example.com+2.pem" {
			t.Errorf("should append +2 for two extra hosts, got %q", certFile)
		}
	})

	t.Run("a wildcard host", func(t *testing.T) {
		// The "*" is not filesystem friendly so it becomes _wildcard.
		m := &mkcert{}
		certFile, _, _ := m.fileNames([]string{"*.example.com"})
		if certFile != "./_wildcard.example.com.pem" {
			t.Errorf("should replace the star with _wildcard, got %q", certFile)
		}
	})

	t.Run("colons are replaced", func(t *testing.T) {
		// IPv6 addresses are full of colons which we cant put in a filename,
		// so they get turned into underscores.
		m := &mkcert{}
		certFile, _, _ := m.fileNames([]string{"::1"})
		if certFile != "./__1.pem" {
			t.Errorf("should replace colons with underscores, got %q", certFile)
		}
	})

	t.Run("client certificates get a -client suffix", func(t *testing.T) {
		m := &mkcert{
			client: true,
		}
		certFile, keyFile, _ := m.fileNames([]string{"example.com"})
		if certFile != "./example.com-client.pem" {
			t.Errorf("should append -client for client certs, got %q", certFile)
		}
		if keyFile != "./example.com-client-key.pem" {
			t.Errorf("should keep -key after the -client suffix, got %q", keyFile)
		}
	})

	t.Run("explicit output paths win", func(t *testing.T) {
		// When the user passes -cert-file and friends those override the
		// computed default names entirely.
		m := &mkcert{
			certFile: "/somewhere/cert.pem",
			keyFile:  "/somewhere/key.pem",
			p12File:  "/somewhere/bundle.p12",
		}
		certFile, keyFile, p12File := m.fileNames([]string{"example.com"})
		if certFile != "/somewhere/cert.pem" {
			t.Errorf("should use the certFile override, got %q", certFile)
		}
		if keyFile != "/somewhere/key.pem" {
			t.Errorf("should use the keyFile override, got %q", keyFile)
		}
		if p12File != "/somewhere/bundle.p12" {
			t.Errorf("should use the p12File override, got %q", p12File)
		}
	})
}

func TestMkcert_GenerateKey(t *testing.T) {
	t.Run("leaf rsa key is 2048 bits", func(t *testing.T) {
		m := &mkcert{}
		key, err := m.generateKey(false)
		if err != nil {
			t.Fatalf("must be able to generate a leaf key: %s", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("should generate an RSA key by default, got %T", key)
		}
		if rsaKey.N.BitLen() != 2048 {
			t.Errorf("should generate a 2048 bit leaf key, got %d", rsaKey.N.BitLen())
		}
	})

	t.Run("root rsa key is 3072 bits", func(t *testing.T) {
		// The CA key is deliberately stronger than the leaf keys it signs.
		m := &mkcert{}
		key, err := m.generateKey(true)
		if err != nil {
			t.Fatalf("must be able to generate a root key: %s", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("should generate an RSA key for the root, got %T", key)
		}
		if rsaKey.N.BitLen() != 3072 {
			t.Errorf("should generate a 3072 bit root key, got %d", rsaKey.N.BitLen())
		}
	})

	t.Run("ecdsa uses the P256 curve", func(t *testing.T) {
		m := &mkcert{
			ecdsa: true,
		}
		key, err := m.generateKey(false)
		if err != nil {
			t.Fatalf("must be able to generate an ecdsa key: %s", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("should generate an ECDSA key when -ecdsa is set, got %T", key)
		}
		if ecKey.Curve != elliptic.P256() {
			t.Errorf("should use the P256 curve, got %s", ecKey.Curve.Params().Name)
		}
	})
}

func TestRandomSerialNumber(t *testing.T) {
	t.Run("is a positive number that fits in 128 bits", func(t *testing.T) {
		serial := randomSerialNumber()
		if serial.Sign() <= 0 {
			t.Error("should be a positive serial number")
		}
		if serial.BitLen() > 128 {
			t.Errorf("should fit within 128 bits, got %d", serial.BitLen())
		}
	})

	t.Run("two serials do not collide", func(t *testing.T) {
		// Not a real randomness test, just a sanity check that we are not
		// handing back a constant.
		a := randomSerialNumber()
		b := randomSerialNumber()
		if a.Cmp(b) == 0 {
			t.Error("two serial numbers should not be equal")
		}
	})
}

func TestMkcert_MakeCert(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// Use a throwaway CAROOT so we never read or write the real CA in
		// the user's home directory. loadCA creates a fresh CA in here.
		caroot := t.TempDir()
		outDir := t.TempDir()
		m := &mkcert{
			CAROOT:   caroot,
			certFile: filepath.Join(outDir, "test.pem"),
			keyFile:  filepath.Join(outDir, "test-key.pem"),
		}

		{ // Create and load the CA. makeCert needs the key to sign with.
			m.loadCA()
			if m.caCert == nil || m.caKey == nil {
				t.Fatal("must have a CA cert and key loaded before making certificates")
			}
		}

		hosts := []string{"example.com", "127.0.0.1", "root@example.com"}
		m.makeCert(hosts)

		// Read back what we just wrote and make sure it really is the cert we
		// asked for. This is the most meaningful thing to assert, the file on
		// disk is the whole product.
		leaf := readCertificate(t, m.certFile)

		{ // The SAN routing, each host type lands in its own field.
			if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
				t.Errorf("should route the hostname into DNSNames, got %v", leaf.DNSNames)
			}
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
				t.Errorf("should route the IP into IPAddresses, got %v", leaf.IPAddresses)
			}
			if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "root@example.com" {
				t.Errorf("should route the email into EmailAddresses, got %v", leaf.EmailAddresses)
			}
		}

		{ // Because we have a DNS/IP host and an email host we expect both
			// serverAuth and emailProtection extended key usages.
			if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
				t.Error("should have serverAuth because there is a DNS/IP host")
			}
			if !hasExtKeyUsage(leaf, x509.ExtKeyUsageEmailProtection) {
				t.Error("should have emailProtection because there is an email host")
			}
		}

		{ // The whole point of mkcert is that the leaf chains up to our CA.
			// Verify it the way a TLS client would.
			roots := x509.NewCertPool()
			roots.AddCert(m.caCert)
			_, err := leaf.Verify(x509.VerifyOptions{
				DNSName: "example.com",
				Roots:   roots,
			})
			if err != nil {
				t.Errorf("should verify against the CA we created: %s", err)
			}
		}

		{ // The key should be written too, as a PKCS#8 PRIVATE KEY block.
			keyPEM, err := os.ReadFile(m.keyFile)
			if err != nil {
				t.Fatalf("must be able to read the generated key: %s", err)
			}
			keyBlock, _ := pem.Decode(keyPEM)
			if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
				t.Error("should write the key as a PKCS#8 PRIVATE KEY block")
			}
		}

		{ // Certificates last 2 years and 3 months, which is the value that
			// keeps us under the 825 day Apple limit. Give it a day of slack.
			wantExpiry := time.Now().AddDate(2, 3, 0)
			if diff := leaf.NotAfter.Sub(wantExpiry); diff > 24*time.Hour || diff < -24*time.Hour {
				t.Errorf("should expire about 2 years 3 months out, got %s", leaf.NotAfter)
			}
		}
	})
}

func TestMkcert_MakeCertFromCSR(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		caroot := t.TempDir()
		outDir := t.TempDir()
		m := &mkcert{
			CAROOT:   caroot,
			certFile: filepath.Join(outDir, "from-csr.pem"),
		}

		{ // Same throwaway CA setup as the makeCert test.
			m.loadCA()
			if m.caCert == nil || m.caKey == nil {
				t.Fatal("must have a CA cert and key loaded before making certificates")
			}
		}

		csrPath := filepath.Join(outDir, "request.csr")
		{ // Build a CSR the way an external tool would, then drop it on disk
			// so makeCertFromCSR can pick it up via m.csrPath like the -csr flag.
			csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("must be able to generate a key for the CSR: %s", err)
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "csr.example.com",
				},
				DNSNames: []string{"csr.example.com"},
			}, csrKey)
			if err != nil {
				t.Fatalf("must be able to create the CSR: %s", err)
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: csrDER,
			})
			if err := os.WriteFile(csrPath, csrPEM, 0600); err != nil {
				t.Fatalf("must be able to write the CSR to disk: %s", err)
			}
		}
		m.csrPath = csrPath

		m.makeCertFromCSR()

		leaf := readCertificate(t, m.certFile)

		if leaf.Subject.CommonName != "csr.example.com" {
			t.Errorf("should carry the CSR subject common name, got %q", leaf.Subject.CommonName)
		}
		// CheckSignatureFrom is enough here, it confirms the CA actually signed
		// the cert we generated from the request.
		if err := leaf.CheckSignatureFrom(m.caCert); err != nil {
			t.Errorf("should be signed by the CA we created: %s", err)
		}
	})
}

// readCertificate reads a PEM file from disk and parses the single certificate
// inside it, failing the test if anything along the way goes wrong.
func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	certPEM, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("must be able to read the generated certificate: %s", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("must be able to decode a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("must be able to parse the generated certificate: %s", err)
	}
	return cert
}

// hasExtKeyUsage reports whether the certificate carries the given extended key
// usage, since the order they get added in is not something we want to assert.
func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}
