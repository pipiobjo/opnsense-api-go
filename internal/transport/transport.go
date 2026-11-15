// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package transport sends requests to the OPNsense API: basic auth with
// key and secret, TLS that is always verified (system roots, a CA, or a
// certificate pin), HTTP/2, error mapping, retries only for GET.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config of a transport.
type Config struct {
	URL     string // https://host[:port], without /api
	Key     string
	Secret  string
	CAPEM   []byte // additional trusted CA certificates (PEM)
	Pin     string // SHA-256 of the server certificate (DER), hex, colons allowed
	Timeout time.Duration
	Logger  *slog.Logger // method, path, status and duration only
	HTTP    *http.Client // replaces the built-in client (tests)
}

// Transport sends requests.
type Transport struct {
	base    *url.URL
	key     string
	secret  string
	timeout time.Duration
	log     *slog.Logger
	hc      *http.Client
}

// ErrUnauthorized: the firewall rejected key and secret (HTTP 401) or the
// key lacks the privilege (HTTP 403).
var ErrUnauthorized = errors.New("opnsense: not authorized (check API key, secret and privileges)")

// HTTPError is a response other than 2xx.
type HTTPError struct {
	Method, Path string
	Status       int
	Body         string // first 300 bytes
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("opnsense: %s %s: HTTP %d %s", e.Method, e.Path, e.Status, e.Body)
}

// NotFound reports HTTP 404 (endpoint not found).
func (e *HTTPError) NotFound() bool { return e.Status == http.StatusNotFound }

// New checks the configuration and builds the HTTP client.
func New(c Config) (*Transport, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("opnsense: URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("opnsense: URL must be https://host[:port], got %q", c.URL)
	}
	if c.Key == "" || c.Secret == "" {
		return nil, errors.New("opnsense: key and secret are required")
	}
	t := &Transport{base: u, key: c.Key, secret: c.Secret, timeout: c.Timeout, log: c.Logger, hc: c.HTTP}
	if t.timeout == 0 {
		t.timeout = 60 * time.Second
	}
	if t.hc == nil {
		tc, err := tlsConfig(c)
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     tc,
			ForceAttemptHTTP2:   true, // large responses arrive broken over HTTP/1.1
			TLSHandshakeTimeout: 15 * time.Second,
			MaxIdleConnsPerHost: 4,
		}
		t.hc = &http.Client{Transport: tr}
	}
	return t, nil
}

func tlsConfig(c Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(c.CAPEM) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(c.CAPEM) {
			return nil, errors.New("opnsense: no certificate found in the CA PEM")
		}
		tc.RootCAs = pool
	}
	if c.Pin != "" {
		want, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(c.Pin), ":", ""))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("opnsense: pin must be the hex SHA-256 of the certificate")
		}
		// The pin replaces chain and name verification: the certificate is
		// trusted because it is exactly this one (self-signed firewalls).
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("opnsense: no server certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("opnsense: server certificate SHA-256 %x does not match the pin", got)
			}
			return nil
		}
	}
	return tc, nil
}

// Get sends a GET (no body, no Content-Type: the server answers 400
// otherwise) and decodes the JSON response into out. Connection errors are
// retried twice.
func (t *Transport) Get(ctx context.Context, path string, out any) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		var retry bool
		retry, err = t.do(ctx, http.MethodGet, path, nil, out, t.timeout)
		if err == nil || !retry {
			return err
		}
	}
	return err
}

// Post sends a JSON body (nil sends "{}") and decodes the response. Never
// retried: a mutation may have been applied even if the answer was lost.
func (t *Transport) Post(ctx context.Context, path string, body, out any, timeout time.Duration) error {
	if timeout == 0 {
		timeout = t.timeout
	}
	_, err := t.do(ctx, http.MethodPost, path, body, out, timeout)
	return err
}

func (t *Transport) do(ctx context.Context, method, path string, body, out any, timeout time.Duration) (retry bool, err error) {
	if !strings.HasPrefix(path, "/api/") {
		return false, fmt.Errorf("opnsense: path must start with /api/: %q", path)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := *t.base
	u.Path = t.base.Path + path
	var rd io.Reader
	if method != http.MethodGet {
		if body == nil {
			body = map[string]any{}
		}
		b, err := json.Marshal(body)
		if err != nil {
			return false, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(t.key, t.secret)
	req.Header.Set("Accept", "application/json")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := t.hc.Do(req)
	if err != nil {
		// do not wrap the url.Error: it carries the URL, never credentials,
		// but keep the message short
		return ctx.Err() == nil && !isTLS(err), fmt.Errorf("opnsense: %s %s: %w", method, path, unwrapURL(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if t.log != nil {
		t.log.Debug("opnsense request", "method", method, "path", path, "status", resp.StatusCode,
			"duration", time.Since(start).Round(time.Millisecond))
	}
	if err != nil {
		return method == http.MethodGet, fmt.Errorf("opnsense: %s %s: reading response: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, ErrUnauthorized
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return false, &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: trunc(raw)}
	}
	if out == nil {
		return false, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("opnsense: %s %s: response is not the expected JSON: %w (%s)", method, path, err, trunc(raw))
	}
	return false, nil
}

// isTLS: a certificate problem does not go away on retry.
func isTLS(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) ||
		strings.Contains(err.Error(), "does not match the pin")
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func trunc(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
