// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
	if err := newT(t, srv).Get(context.Background(), "/api/x", &out); err != nil || out["ok"] != true {
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
	if err := tr.Get(ctx, "/api/ok", &out); err != nil || gotCT != "" || gotBody != "" {
		t.Errorf("GET must have neither body nor Content-Type: %v %q %q", err, gotCT, gotBody)
	}
	if err := tr.Post(ctx, "/api/ok", nil, &out, 0); err != nil || gotCT != "application/json" || gotBody != "{}" {
		t.Errorf("POST without body sends {}: %v %q %q", err, gotCT, gotBody)
	}
	if err := tr.Get(ctx, "/api/denied", &out); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("403: %v", err)
	}
	var he *HTTPError
	if err := tr.Get(ctx, "/api/missing", &out); !errors.As(err, &he) || !he.NotFound() {
		t.Errorf("404: %v", err)
	}
	if err := tr.Get(ctx, "/api/html", &out); err == nil || !strings.Contains(err.Error(), "not the expected JSON") {
		t.Errorf("non-JSON: %v", err)
	}
	if err := tr.Get(ctx, "/other", &out); err == nil {
		t.Error("paths outside /api/ must be refused")
	}
	if _, err := New(Config{URL: "https://192.0.2.1", Key: "k"}); err == nil {
		t.Error("a missing secret must be refused")
	}
	if _, err := New(Config{URL: "https://192.0.2.1", Key: "k", Secret: "s", Pin: "zz"}); err == nil {
		t.Error("a malformed pin must be refused")
	}
}
