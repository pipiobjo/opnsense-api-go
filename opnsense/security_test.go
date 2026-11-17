// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim (README, SECURITY.md): key and secret never appear in an error or
// in the debug log, whatever goes wrong. Every failure path a caller can
// reach is driven once with distinctive credentials, and every error text
// and the whole debug log are searched for them.
func TestCredentialsNeverInErrorsOrLogs(t *testing.T) {
	const key, secret = "KEY-7f3a9c-sentinel", "SECRET-b41e07-sentinel"
	ctx := context.Background()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f := newFake(t)
	f.key, f.secret = key, secret
	withCreds := func(c *Config) { c.Key, c.Secret, c.Logger = key, secret, logger }

	var errs []error
	note := func(err error) {
		if err == nil {
			t.Error("a failure path did not fail; the test no longer drives it")
			return
		}
		errs = append(errs, err)
	}

	// connection-level failures
	_, err := connect(t, f, withCreds, func(c *Config) { c.Secret = secret + "-wrong" })
	note(err)
	_, err = connect(t, f, withCreds, func(c *Config) { c.TLS.PinSHA256 = strings.Repeat("ab", 32) })
	note(err)
	_, err = connect(t, f, withCreds, func(c *Config) { c.TLS = TLS{} })
	note(err)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := "https://" + l.Addr().String()
	l.Close()
	_, err = connect(t, f, withCreds, func(c *Config) { c.URL = closed })
	note(err)
	_, err = connect(t, f, withCreds, func(c *Config) { c.URL = "https://" + key + ":" + secret + "@192.0.2.1" })
	note(err)

	// API-level failures on a working connection
	c, err := connect(t, f, withCreds)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.Entries(neighbors)
	_, err = n.Add(ctx, Values{"address": "not-an-address"}) // ErrValidation
	note(err)
	_, err = n.Add(ctx, Values{"nosuchfield": "x"}) // ErrFieldNotAvailable
	note(err)
	err = n.Set(ctx, "00000000-0000-4000-8000-00000000dead", Values{"description": "x"}) // ErrNotFound
	note(err)
	f.dropSets["routerid"] = true
	s, _ := c.Settings("quagga/ospfsettings")
	note(s.Set(ctx, Values{"routerid": "192.0.2.1"})) // ErrNotApplied
	f.applyAnswer = map[string]any{"status": "failed"}
	note(c.Apply(ctx)) // ErrApply
	f.infoStatus = 403
	c2, err := connect(t, f, withCreds) // a missing firmware privilege: New continues
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Entries(neighbors) // ErrNotAvailable with PluginsUnknown
	note(err)

	for _, e := range errs {
		if msg := e.Error(); strings.Contains(msg, key) || strings.Contains(msg, secret) {
			t.Errorf("credentials in an error: %s", msg)
		}
	}
	if logBuf.Len() == 0 {
		t.Fatal("the debug log is empty; the logger is not wired, so the log check proves nothing")
	}
	if log := logBuf.String(); strings.Contains(log, key) || strings.Contains(log, secret) {
		t.Errorf("credentials in the debug log:\n%s", log)
	}
}

// Claim (README, TLS): a CA verifies the firewall's certificate, chain and
// name; a CA that did not sign it, or input that is no certificate, fails
// before anything is sent.
func TestTLSWithCA(t *testing.T) {
	f := newFake(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{CAPEM: caPEM} }); err != nil {
		t.Errorf("CA PEM of the server: %v", err)
	}
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{CAFile: file} }); err != nil {
		t.Errorf("CA file of the server: %v", err)
	}
	otherPEM := otherCA(t) // httptest servers all share one certificate
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{CAPEM: otherPEM} }); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a CA that did not sign the certificate must fail: %v", err)
	}
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{CAPEM: []byte("not a certificate")} }); err == nil {
		t.Error("input without a certificate must be refused")
	}
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{CAFile: filepath.Join(t.TempDir(), "missing.pem")} }); err == nil {
		t.Error("a missing CA file must be refused")
	}
	for _, pin := range []string{"zz", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{PinSHA256: pin} }); err == nil {
			t.Errorf("pin %q must be refused", pin)
		}
	}
	// colon-separated upper case, as browsers show it
	colon := strings.ToUpper(f.pin()[:2])
	for i := 2; i < len(f.pin()); i += 2 {
		colon += ":" + strings.ToUpper(f.pin()[i:i+2])
	}
	if _, err := connect(t, f, func(c *Config) { c.TLS = TLS{PinSHA256: colon} }); err != nil {
		t.Errorf("pin in colon notation: %v", err)
	}
	_, err := connect(t, f, func(c *Config) { c.TLS = TLS{PinSHA256: strings.Repeat("ab", 32)} })
	if err == nil || !strings.Contains(err.Error(), f.pin()) {
		t.Errorf("a pin mismatch names the certificate's actual SHA-256: %v", err)
	}
}

// otherCA returns a freshly generated self-signed CA certificate that did
// not sign the fake's certificate.
func otherCA(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
