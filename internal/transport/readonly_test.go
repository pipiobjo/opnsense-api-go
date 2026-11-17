// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Claim K9, second line: a read-only transport sends no POST except a
// search with the fixed paging body, and no GET or search outside its
// readable list, whatever the layer above asks for.
func TestReadOnlyTransport(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(b))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"rows":[],"total":0}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	tr, err := New(Config{URL: srv.URL, Key: "k", Secret: "s", HTTP: srv.Client(), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := tr.Get(ctx, "/api/a/b/get", nil, &out); !errors.Is(err, ErrWriteRefused) {
		t.Errorf("GET before SetReadable: %v", err)
	}
	if err := tr.Get(ctx, "/api/core/firmware/info", nil, &out); err != nil {
		t.Errorf("GET of a detection path: %v", err)
	}
	tr.SetReadable([]string{"/api/a/b/get/*", "/api/a/b/searchItem", "/api/x/status"})
	if err := tr.Get(ctx, "/api/a/b/get", nil, &out); err != nil {
		t.Errorf("GET: %v", err)
	}
	for _, p := range []string{"/api/core/system/reboot", "/api/a/b/getter", "/api/x/status/start", "/api/a/b/searchItem/x"} {
		if err := tr.Get(ctx, p, nil, &out); !errors.Is(err, ErrWriteRefused) {
			t.Errorf("GET %s is not readable: %v", p, err)
		}
	}
	if err := tr.Search(ctx, "/api/a/b/searchItem", &out); err != nil {
		t.Errorf("search: %v", err)
	}
	if err := tr.Post(ctx, "/api/a/b/searchItem", map[string]any{"x": 1}, &out, 0); !errors.Is(err, ErrWriteRefused) {
		t.Errorf("POST in read-only mode: %v", err)
	}
	if err := tr.Post(ctx, "/api/a/b/set", nil, &out, 0); !errors.Is(err, ErrWriteRefused) {
		t.Errorf("POST set in read-only mode: %v", err)
	}
	if err := tr.Search(ctx, "/api/a/b/setItem", &out); !errors.Is(err, ErrWriteRefused) {
		t.Errorf("Search on a path that is no search: %v", err)
	}
	rw, _ := New(Config{URL: srv.URL, Key: "k", Secret: "s", HTTP: srv.Client()})
	if err := rw.Post(ctx, "/api/a/b/set", nil, &out, 0); err != nil {
		t.Errorf("POST without read-only mode: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	seen = seen[:len(seen)-1] // the POST of the writing transport
	if len(seen) != 3 {
		t.Fatalf("requests: %q", seen)
	}
	var body map[string]any
	if seen[0] != "GET /api/core/firmware/info " || seen[1] != "GET /api/a/b/get " {
		t.Errorf("first requests: %q", seen[:2])
	}
	if err := json.Unmarshal([]byte(seen[2][len("POST /api/a/b/searchItem "):]), &body); err != nil ||
		len(body) != 2 || body["current"] != float64(1) || body["rowCount"] != float64(-1) {
		t.Errorf("search body: %q", seen[2])
	}

}
