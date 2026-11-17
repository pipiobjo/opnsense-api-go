// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only a missing privilege (403) falls back to "core only". Any other
// failure of firmware/info (500, a timeout) fails New: a client that
// believes no plugin is installed would mislead for its whole life.
func TestDetectionFallbackOnlyOnForbidden(t *testing.T) {
	f := newFake(t)
	f.infoStatus = http.StatusInternalServerError
	if _, err := connect(t, f); err == nil || !strings.Contains(err.Error(), "firmware/info") {
		t.Errorf("HTTP 500 on firmware/info must fail New: %v", err)
	}
	f2 := newFake(t)
	f2.infoStatus = http.StatusForbidden
	c := mustConnect(t, f2)
	_, err := c.Entries(neighbors)
	var na *ErrNotAvailable
	if !errors.As(err, &na) || !na.PluginsUnknown || !strings.Contains(err.Error(), "plugin list is unknown") {
		t.Errorf("without the plugin list the error must say so, not \"not installed\": %v", err)
	}
}

// An own HTTP client cannot be combined with TLS settings: they would be
// ignored silently, the pin included.
func TestHTTPClientWithTLSIsRefused(t *testing.T) {
	f := newFake(t)
	for name, tls := range map[string]TLS{
		"pin":      {PinSHA256: f.pin()},
		"ca":       {CAPEM: []byte("x")},
		"insecure": {InsecureSkipVerify: true},
	} {
		_, err := connect(t, f, func(c *Config) { c.HTTPClient = f.srv.Client(); c.TLS = tls })
		if err == nil || !strings.Contains(err.Error(), "HTTPClient") {
			t.Errorf("%s: HTTPClient together with TLS settings must be refused: %v", name, err)
		}
	}
	if _, err := connect(t, f, func(c *Config) { c.HTTPClient = f.srv.Client(); c.TLS = TLS{} }); err != nil {
		t.Errorf("HTTPClient alone is allowed: %v", err)
	}
}

// The data directory is opened as a root: a symbolic link inside it that
// points outside is not followed.
func TestCapabilityDirSymlinkOutside(t *testing.T) {
	dir := t.TempDir()
	src := "capability/testdata/catalog"
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	b, _ := os.ReadFile(filepath.Join(src, "capabilities", "os-frr.json"))
	if err := os.WriteFile(outside, b, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "capabilities", "os-frr.json")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symbolic links not supported here")
	}
	f := newFake(t)
	_, err := New(context.Background(), Config{URL: f.srv.URL, Key: "key", Secret: "secret", TLS: TLS{PinSHA256: f.pin()}, CapabilityDir: dir})
	if err == nil {
		t.Error("a symbolic link to a file outside the data directory must not be followed")
	}
}
