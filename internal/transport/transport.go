// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package transport sends requests to the OPNsense API: basic auth with
// key and secret, TLS verified against the system roots, a CA or a
// certificate pin (or deliberately not at all), HTTP/2, no redirects,
// error mapping, retries only for GET.
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
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// MaxResponse is the largest response body that is read (the firmware
// info of a firewall with all plugins is about 1 MB).
const MaxResponse = 64 << 20

var maxResponse = MaxResponse // lowered in tests

// Config of a transport.
type Config struct {
	URL    string // https://host[:port][/path], without /api
	Key    string
	Secret string
	CAPEM  []byte // additional trusted CA certificates (PEM)
	Pin    string // SHA-256 of the server certificate (DER), hex, colons allowed
	// Insecure disables certificate verification entirely. Anyone on the
	// network path can then read the API key and secret.
	Insecure bool
	Timeout  time.Duration
	Logger   *slog.Logger // method, path, status and duration only
	HTTP     *http.Client // replaces the built-in client (tests); redirects are still refused
	// ReadOnly refuses every POST except Search. The client checks its
	// own methods first; this is the second line, independent of them.
	ReadOnly bool
}

// Transport sends requests. It is safe for concurrent use.
type Transport struct {
	base    *url.URL
	key     string
	secret  string
	timeout time.Duration
	log     *slog.Logger
	hc      *http.Client
	ro      bool
}

// ErrWriteRefused: the transport is read-only and the request could change
// the firewall; it was not sent.
var ErrWriteRefused = errors.New("opnsense: read-only mode: request refused before sending")

// ErrOutcomeUnknown: a POST reached the firewall, but its answer was lost,
// unreadable or a server error (HTTP 5xx). The change may have been saved.
// The error keeps its cause (errors.As finds an *HTTPError, for example).
var ErrOutcomeUnknown = errors.New("opnsense: request sent, outcome unknown")

type outcomeUnknown struct{ err error }

func (e *outcomeUnknown) Error() string {
	return e.err.Error() + " (the request reached the firewall; it may have taken effect)"
}
func (e *outcomeUnknown) Unwrap() error        { return e.err }
func (e *outcomeUnknown) Is(target error) bool { return target == ErrOutcomeUnknown }

// ErrUnauthorized: the firewall rejected key and secret (HTTP 401).
var ErrUnauthorized = errors.New("opnsense: authentication failed (check API key and secret)")

// ErrForbidden: the key is valid but lacks the privilege (HTTP 403).
var ErrForbidden = errors.New("opnsense: the API key lacks the privilege for this endpoint")

// HTTPError is a response other than 2xx.
type HTTPError struct {
	Method, Path string
	Status       int
	Body         string // at most 300 bytes
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("opnsense: %s %s: HTTP %d %s", e.Method, e.Path, e.Status, e.Body)
}

// NotFound reports HTTP 404 (endpoint not found).
func (e *HTTPError) NotFound() bool { return e.Status == http.StatusNotFound }

// New checks the configuration and builds the HTTP client.
func New(c Config) (*Transport, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, errors.New("opnsense: the URL cannot be parsed")
	}
	switch {
	case u.Scheme != "https" || u.Host == "":
		return nil, errors.New("opnsense: URL must be https://host[:port]")
	case u.User != nil:
		// never echo it: it contains credentials
		return nil, errors.New("opnsense: the URL must not contain user or password; use Key and Secret")
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("opnsense: the URL must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	if c.Key == "" || c.Secret == "" {
		return nil, errors.New("opnsense: key and secret are required")
	}
	t := &Transport{base: u, key: c.Key, secret: c.Secret, timeout: c.Timeout, log: c.Logger, ro: c.ReadOnly}
	if t.timeout == 0 {
		t.timeout = 60 * time.Second
	}
	if c.HTTP != nil {
		hc := *c.HTTP
		t.hc = &hc
	} else {
		tc, err := tlsConfig(c)
		if err != nil {
			return nil, err
		}
		t.hc = &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     tc,
			ForceAttemptHTTP2:   true, // large responses arrive broken over HTTP/1.1
			TLSHandshakeTimeout: 15 * time.Second,
			MaxIdleConnsPerHost: 4,
		}}
	}
	// A redirect could lead to plain http (Go keeps the Authorization
	// header for the same host) or resend a mutation elsewhere.
	t.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return t, nil
}

func tlsConfig(c Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	trust := 0
	for _, set := range []bool{c.Insecure, c.Pin != "", len(c.CAPEM) > 0} {
		if set {
			trust++
		}
	}
	if trust > 1 {
		return nil, errors.New("opnsense: choose one of CA, pin or InsecureSkipVerify")
	}
	switch {
	case c.Insecure:
		tc.InsecureSkipVerify = true
	case len(c.CAPEM) > 0:
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(c.CAPEM) {
			return nil, errors.New("opnsense: no certificate found in the CA PEM")
		}
		tc.RootCAs = pool
	case c.Pin != "":
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
				return &PinError{Got: hex.EncodeToString(got[:])}
			}
			return nil
		}
	}
	return tc, nil
}

// PinError: the server certificate does not match the pin.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	return "opnsense: server certificate SHA-256 " + e.Got + " does not match the pin"
}

// Get sends a GET (no body, no Content-Type: the server answers 400
// otherwise) and decodes the JSON response into out. Connection errors are
// retried twice, certificate errors never.
func (t *Transport) Get(ctx context.Context, path string, query url.Values, out any) error {
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
		retry, err = t.do(ctx, http.MethodGet, path, query, nil, out, t.timeout)
		if err == nil || !retry {
			return err
		}
	}
	return err
}

// Post sends a JSON body (nil sends "{}") and decodes the response. Never
// retried: a mutation may have been applied even if the answer was lost.
// When the request was written but no valid answer came back (connection
// lost, unreadable body, HTTP 5xx), the error matches ErrOutcomeUnknown.
func (t *Transport) Post(ctx context.Context, path string, body, out any, timeout time.Duration) error {
	if t.ro {
		return fmt.Errorf("%w: POST %s", ErrWriteRefused, path)
	}
	if timeout == 0 {
		timeout = t.timeout
	}
	var wrote atomic.Bool // set from the transport's write goroutine
	trace := &httptrace.ClientTrace{WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			wrote.Store(true)
		}
	}}
	_, err := t.do(httptrace.WithClientTrace(ctx, trace), http.MethodPost, path, nil, body, out, timeout)
	var he *HTTPError
	switch {
	case err == nil:
	case errors.As(err, &he):
		if he.Status >= 500 {
			return &outcomeUnknown{err}
		}
	case wrote.Load() && !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrForbidden):
		return &outcomeUnknown{err}
	}
	return err
}

// Search lists all rows of an entry list: a POST with the fixed body
// {"current": 1, "rowCount": -1}, for search endpoints that accept only
// POST. Allowed in read-only mode, so nothing a caller passes ends up in
// the body, and the last path segment must name a search ("search...", as
// every search operation in the capability data does).
func (t *Transport) Search(ctx context.Context, path string, out any) error {
	last := path[strings.LastIndex(path, "/")+1:]
	if !strings.HasPrefix(strings.ToLower(last), "search") {
		return fmt.Errorf("%w: %s is not a search endpoint", ErrWriteRefused, path)
	}
	_, err := t.do(ctx, http.MethodPost, path, nil, map[string]any{"current": 1, "rowCount": -1}, out, t.timeout)
	return err
}

// CheckPath accepts /api/<segment>/... with segments of letters, digits,
// '_', '-' and '.', but no "." or ".." segment. Everything the client
// sends goes through it, so no input can leave the API or need escaping.
func CheckPath(p string) error {
	if !strings.HasPrefix(p, "/api/") {
		return fmt.Errorf("opnsense: path must start with /api/: %q", p)
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("opnsense: invalid path %q", p)
		}
		for _, r := range seg {
			ok := r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !ok {
				return fmt.Errorf("opnsense: invalid character %q in path %q", r, p)
			}
		}
	}
	return nil
}

func (t *Transport) do(ctx context.Context, method, path string, query url.Values, body, out any, timeout time.Duration) (retry bool, err error) {
	if err := CheckPath(path); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := *t.base
	u.Path = t.base.Path + path // no escaping needed: CheckPath allows only safe characters
	u.RawQuery = query.Encode()
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
		return ctx.Err() == nil && !isTLS(err), fmt.Errorf("opnsense: %s %s: %w", method, path, unwrapURL(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	if t.log != nil {
		t.log.Debug("opnsense request", "method", method, "path", path, "status", resp.StatusCode,
			"duration", time.Since(start).Round(time.Millisecond))
	}
	if err != nil {
		return method == http.MethodGet, fmt.Errorf("opnsense: %s %s: reading response: %w", method, path, err)
	}
	if len(raw) > maxResponse {
		return false, fmt.Errorf("opnsense: %s %s: response larger than %d bytes", method, path, maxResponse)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return false, ErrUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return false, fmt.Errorf("%w (%s %s)", ErrForbidden, method, path)
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		return false, &HTTPError{Method: method, Path: path, Status: resp.StatusCode,
			Body: "redirect refused (check the URL; the API is not followed to another location)"}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return false, &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: Trunc(raw)}
	}
	if out == nil {
		return false, nil
	}
	if method == http.MethodPost && len(bytes.TrimSpace(raw)) == 0 {
		// some endpoints answer nothing (gap result-not-returned): out stays
		// unchanged and the caller decides how to confirm the effect
		return false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exact; values are strings on the wire anyway
	if err := dec.Decode(out); err != nil {
		// the body is left out: a cut-off configuration may contain secrets
		return false, fmt.Errorf("opnsense: %s %s: response is not the expected JSON (%d bytes): %w", method, path, len(raw), err)
	}
	return false, nil
}

// isTLS: a certificate problem does not go away on retry.
func isTLS(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var pe *PinError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &pe)
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Trunc shortens a response for an error message.
func Trunc(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
