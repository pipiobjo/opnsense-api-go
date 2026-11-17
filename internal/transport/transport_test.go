// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flaky drops the connection of the first request, then answers.
func flaky(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("no hijacker")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func newT(t *testing.T, srv *httptest.Server) *Transport {
	tr, err := New(Config{URL: srv.URL, Key: "k", Secret: "s", HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestGetIsRetriedPostIsNot(t *testing.T) {
	srv, n := flaky(t)
	var out map[string]any
	if err := newT(t, srv).Get(context.Background(), "/api/x", nil, &out); err != nil || out["ok"] != true {
		t.Errorf("GET after a dropped connection: %v %v", out, err)
	}
	if n.Load() != 2 {
		t.Errorf("GET attempts: %d", n.Load())
	}
	srv2, n2 := flaky(t)
	if err := newT(t, srv2).Post(context.Background(), "/api/x", nil, &out, 0); err == nil {
		t.Error("POST must not be retried after a dropped connection")
	}
	if n2.Load() != 1 {
		t.Errorf("POST attempts: %d", n2.Load())
	}
}

func TestErrorsAndRequestShape(t *testing.T) {
	var gotCT, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		b := make([]byte, 100)
		k, _ := r.Body.Read(b)
		gotBody = string(b[:k])
		switch r.URL.Path {
		case "/api/denied":
			w.WriteHeader(403)
		case "/api/missing":
			w.WriteHeader(404)
			w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
		case "/api/html":
			w.Write([]byte(`<html>login</html>`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	tr := newT(t, srv)
	ctx := context.Background()
	var out any
	if err := tr.Get(ctx, "/api/ok", nil, &out); err != nil || gotCT != "" || gotBody != "" {
		t.Errorf("GET must have neither body nor Content-Type: %v %q %q", err, gotCT, gotBody)
	}
	if err := tr.Post(ctx, "/api/ok", nil, &out, 0); err != nil || gotCT != "application/json" || gotBody != "{}" {
		t.Errorf("POST without body sends {}: %v %q %q", err, gotCT, gotBody)
	}
	if err := tr.Get(ctx, "/api/denied", nil, &out); !errors.Is(err, ErrForbidden) {
		t.Errorf("403: %v", err)
	}
	var he *HTTPError
	if err := tr.Get(ctx, "/api/missing", nil, &out); !errors.As(err, &he) || !he.NotFound() {
		t.Errorf("404: %v", err)
	}
	if err := tr.Get(ctx, "/api/html", nil, &out); err == nil || !strings.Contains(err.Error(), "not the expected JSON") {
		t.Errorf("non-JSON: %v", err)
	}
	if err := tr.Get(ctx, "/other", nil, &out); err == nil {
		t.Error("paths outside /api/ must be refused")
	}
	if _, err := New(Config{URL: "https://192.0.2.1", Key: "k"}); err == nil {
		t.Error("a missing secret must be refused")
	}
	if _, err := New(Config{URL: "https://192.0.2.1", Key: "k", Secret: "s", Pin: "zz"}); err == nil {
		t.Error("a malformed pin must be refused")
	}
}

func TestQueryRedirectAndSize(t *testing.T) {
	var gotPath, gotQuery string
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath, gotQuery = r.URL.EscapedPath(), r.URL.RawQuery
		switch r.URL.Path {
		case "/api/redirect":
			http.Redirect(w, r, "http://"+r.Host+"/api/plain", http.StatusFound)
		case "/api/big":
			w.Write([]byte(`"` + strings.Repeat("x", 100) + `"`))
		case "/api/empty":
			// nothing
		case "/api/number":
			w.Write([]byte(`{"n": 9007199254740993}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	tr := newT(t, srv)
	ctx := context.Background()
	var out any
	if err := tr.Get(ctx, "/api/x/search", url.Values{"rowCount": {"-1"}}, &out); err != nil ||
		gotPath != "/api/x/search" || gotQuery != "rowCount=-1" {
		t.Errorf("query must not end up in the path: %v %q %q", err, gotPath, gotQuery)
	}
	hits.Store(0)
	if err := tr.Post(ctx, "/api/redirect", nil, &out, 0); err == nil || !strings.Contains(err.Error(), "redirect refused") || hits.Load() != 1 {
		t.Errorf("redirect must be refused, not followed: %v (%d requests)", err, hits.Load())
	}
	var m map[string]any
	if err := tr.Get(ctx, "/api/number", nil, &m); err != nil || m["n"].(json.Number).String() != "9007199254740993" {
		t.Errorf("numbers must stay exact: %v %v", m, err)
	}
	m = map[string]any{"kept": true}
	if err := tr.Post(ctx, "/api/empty", nil, &m, 0); err != nil || m["kept"] != true {
		t.Errorf("an empty POST answer leaves out unchanged: %v %v", m, err)
	}
	if err := tr.Get(ctx, "/api/empty", nil, &m); err == nil {
		t.Error("an empty GET answer is an error")
	}
	old := maxResponse
	maxResponse = 50
	defer func() { maxResponse = old }()
	if err := tr.Get(ctx, "/api/big", nil, &out); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized response: %v", err)
	}
}

func TestConfigChecks(t *testing.T) {
	bad := []Config{
		{URL: "https://key:topsecret@192.0.2.1", Key: "k", Secret: "s"},
		{URL: "https://192.0.2.1/?x=1", Key: "k", Secret: "s"},
		{URL: "https://192.0.2.1/#frag", Key: "k", Secret: "s"},
		{URL: "http://192.0.2.1", Key: "k", Secret: "s"},
		{URL: "192.0.2.1", Key: "k", Secret: "s"},
		{URL: "https://192.0.2.1", Key: "k", Secret: "s", Insecure: true, Pin: strings.Repeat("ab", 32)},
		{URL: "https://192.0.2.1", Key: "k", Secret: "s", Pin: strings.Repeat("ab", 32), CAPEM: []byte("x")},
	}
	for _, c := range bad {
		_, err := New(c)
		if err == nil {
			t.Errorf("accepted: %+v", c)
			continue
		}
		if strings.Contains(err.Error(), "topsecret") {
			t.Errorf("credentials in the error: %v", err)
		}
	}
	if _, err := New(Config{URL: "https://192.0.2.1:8443/", Key: "k", Secret: "s", Insecure: true}); err != nil {
		t.Errorf("insecure alone must be accepted: %v", err)
	}
}

func TestCheckPath(t *testing.T) {
	for _, p := range []string{"/api/core/firmware/info", "/api/quagga/ospfsettings/getNeighbor/00000000-0000-4000-8000-000000000001", "/api/a_b/c-d/e.f"} {
		if err := CheckPath(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/api/", "/api/a//b", "/api/a/../b", "/api/a/./b", "/api/a/%2e%2e", "/api/a b", "/api/a?b=1", "/api/a#b", "/other/x", "api/x", "/api/a/ä"} {
		if err := CheckPath(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestUnauthorizedAndForbiddenDiffer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/a" {
			w.WriteHeader(401)
		} else {
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	tr := newT(t, srv)
	var out any
	if err := tr.Get(context.Background(), "/api/a", nil, &out); !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden) {
		t.Errorf("401: %v", err)
	}
	if err := tr.Get(context.Background(), "/api/b", nil, &out); !errors.Is(err, ErrForbidden) || errors.Is(err, ErrUnauthorized) {
		t.Errorf("403: %v", err)
	}
}

// A POST that reached the server without a valid answer (connection
// dropped, broken JSON, HTTP 5xx) is ErrOutcomeUnknown, keeping its cause;
// a 4xx, a refused credential or an unreachable server is not.
func TestPostOutcomeUnknown(t *testing.T) {
	ctx := context.Background()
	var out map[string]any
	srv, _ := flaky(t)
	if err := newT(t, srv).Post(ctx, "/api/x", nil, &out, 0); !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("dropped connection after the request: %v, want ErrOutcomeUnknown", err)
	}
	for status, want := range map[int]bool{500: true, 502: true, 400: false, 404: false, 401: false, 403: false} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		err := newT(t, srv).Post(ctx, "/api/x", nil, &out, 0)
		srv.Close()
		if errors.Is(err, ErrOutcomeUnknown) != want {
			t.Errorf("HTTP %d: %v, outcome unknown want %v", status, err, want)
		}
		var he *HTTPError
		if status >= 500 && !errors.As(err, &he) {
			t.Errorf("HTTP %d: the cause must stay an *HTTPError: %v", status, err)
		}
	}
	garbled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"res`)) }))
	defer garbled.Close()
	if err := newT(t, garbled).Post(ctx, "/api/x", nil, &out, 0); !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("broken JSON: %v, want ErrOutcomeUnknown", err)
	}
	gone := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tr := newT(t, gone)
	gone.Close()
	if err := tr.Post(ctx, "/api/x", nil, &out, 0); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("unreachable server: %v, must not be outcome unknown", err)
	}
}

// A cut-off answer may hold configuration secrets: the error names its
// size, not its content.
func TestBrokenJSONIsNotQuoted(t *testing.T) {
	const secret = "PSK-91c2-sentinel"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ipsec":{"psk":"` + secret))
	}))
	defer srv.Close()
	var out map[string]any
	err := newT(t, srv).Get(context.Background(), "/api/x", nil, &out)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("broken JSON: %v", err)
	}
}

// Reads are retried with growing waits after connection errors and HTTP
// 502/503/504 (the web GUI restarting), up to len(RetryDelays) times; a
// search is retried like a GET; other statuses and POST never.
func TestReadRetries(t *testing.T) {
	saved := RetryDelays
	RetryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	defer func() { RetryDelays = saved }()
	ctx := context.Background()
	var out map[string]any
	busy := func(failures int32, status int) (*httptest.Server, *atomic.Int32) {
		var n atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) <= failures {
				w.WriteHeader(status)
				return
			}
			w.Write([]byte(`{"ok":true}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &n
	}
	for _, status := range []int{502, 503, 504} {
		srv, n := busy(3, status)
		if err := newT(t, srv).Get(ctx, "/api/x", nil, &out); err != nil || n.Load() != 4 {
			t.Errorf("HTTP %d three times: %v after %d attempts", status, err, n.Load())
		}
	}
	srv, n := busy(10, 503)
	var he *HTTPError
	if err := newT(t, srv).Get(ctx, "/api/x", nil, &out); !errors.As(err, &he) || n.Load() != int32(len(RetryDelays)+1) {
		t.Errorf("busy for good: %v after %d attempts, want %d", err, n.Load(), len(RetryDelays)+1)
	}
	srv, n = busy(1, 500)
	if err := newT(t, srv).Get(ctx, "/api/x", nil, &out); err == nil || n.Load() != 1 {
		t.Errorf("HTTP 500 must not be retried: %v after %d attempts", err, n.Load())
	}
	srv, n = busy(1, 503)
	if err := newT(t, srv).Search(ctx, "/api/x/searchItem", &out); err != nil || n.Load() != 2 {
		t.Errorf("search after 503: %v after %d attempts", err, n.Load())
	}
	srv, n = busy(1, 503)
	if err := newT(t, srv).Post(ctx, "/api/x/set", nil, &out, 0); err == nil || n.Load() != 1 {
		t.Errorf("POST must not be retried: %v after %d attempts", err, n.Load())
	}
	srv2, n2 := flaky(t)
	if err := newT(t, srv2).Search(ctx, "/api/x/searchItem", &out); err != nil || n2.Load() != 2 {
		t.Errorf("search after a dropped connection: %v after %d attempts", err, n2.Load())
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	srv, _ = busy(10, 503)
	if err := newT(t, srv).Get(cctx, "/api/x", nil, &out); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context ends the retries: %v", err)
	}
}

// The built-in transport speaks HTTP/2: OPNsense's web server cuts large
// answers over HTTP/1.1 (broken chunked encoding). A custom
// Config.HTTPClient must do the same (README).
func TestDefaultTransportUsesHTTP2(t *testing.T) {
	var proto atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		w.Write([]byte(`{}`))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	tr, err := New(Config{URL: srv.URL, Key: "k", Secret: "s", Pin: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := tr.Get(context.Background(), "/api/x", nil, &out); err != nil {
		t.Fatal(err)
	}
	if proto.Load() != 2 {
		t.Errorf("the built-in transport used HTTP/%d, want HTTP/2", proto.Load())
	}
}
