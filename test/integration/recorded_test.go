// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// raw talks to the VM without the client, so the client's own checks
// cannot hide what OPNsense does. Loopback only (checked).
type raw struct {
	t        *testing.T
	base     string
	key, sec string
	http     *http.Client
}

func newRaw(t *testing.T) *raw {
	t.Helper()
	base := os.Getenv("OPNSENSE_URL")
	u, err := url.Parse(base)
	if err != nil || u.Hostname() != "127.0.0.1" {
		t.Fatalf("OPNSENSE_URL must point at the throwaway VM on 127.0.0.1, got %q", base)
	}
	var k struct{ Key, Secret string }
	b, err := os.ReadFile(os.Getenv("OPNSENSE_KEYFILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	return &raw{t: t, base: base, key: k.Key, sec: k.Secret, http: &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} // loopback only, checked above
}

// do sends method path with an optional JSON body and returns the status
// and the decoded answer (nil if it is not JSON).
func (r *raw) do(method, path string, body any, contentType bool) (int, any) {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.base+path, rd)
	if err != nil {
		r.t.Fatal(err)
	}
	req.SetBasicAuth(r.key, r.sec)
	if contentType {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var v any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &v)
	return resp.StatusCode, v
}

// TestRecordedBehaviour checks, on the real firewall, the behaviour the
// unit tests' fake firewall reproduces (opnsense/fake_test.go, recorded on
// 26.7.9 on 2026-11-15). If OPNsense changes one of these, this test goes
// red while the unit tests would stay green.
func TestRecordedBehaviour(t *testing.T) {
	r := newRaw(t)
	const p = "/api/quagga/ospfsettings/"
	if code, _ := r.do("GET", p+"searchNeighbor", nil, false); code == 404 {
		missing(t, errors.New("os-frr not installed"))
	}
	const unknown = "00000000-0000-4000-8000-0000000000ff"
	cleanup := func(id string) { r.do("POST", p+"delNeighbor/"+id, nil, false) }

	t.Run("unknown keys are ignored and the answer is still saved", func(t *testing.T) {
		code, v := r.do("POST", p+"addNeighbor", map[string]any{"neighbor": map[string]any{
			"address": "192.0.2.21", "bogus": "x", "nested": map[string]any{"bogus": "y"}}}, true)
		out, _ := v.(map[string]any)
		id, _ := out["uuid"].(string)
		if id != "" {
			defer cleanup(id)
		}
		if code != 200 || out["result"] != "saved" || id == "" {
			t.Fatalf("add with unknown keys: HTTP %d %v", code, v)
		}
		_, g := r.do("GET", p+"getNeighbor/"+id, nil, false)
		n, _ := g.(map[string]any)["neighbor"].(map[string]any)
		if _, ok := n["bogus"]; ok || n == nil {
			t.Errorf("unknown key stored or entry unreadable: %v", g)
		}
	})

	t.Run("get of an unknown UUID answers []", func(t *testing.T) {
		code, v := r.do("GET", p+"getNeighbor/"+unknown, nil, false)
		if arr, ok := v.([]any); code != 200 || !ok || len(arr) != 0 {
			t.Errorf("HTTP %d %v", code, v)
		}
	})

	t.Run("set with an unknown UUID creates the entry", func(t *testing.T) {
		code, v := r.do("POST", p+"setNeighbor/"+unknown, map[string]any{"neighbor": map[string]any{"address": "192.0.2.22"}}, true)
		defer cleanup(unknown)
		if out, _ := v.(map[string]any); code != 200 || out["result"] != "saved" {
			t.Fatalf("set: HTTP %d %v", code, v)
		}
		_, g := r.do("GET", p+"getNeighbor/"+unknown, nil, false)
		n, _ := g.(map[string]any)["neighbor"].(map[string]any)
		if n == nil {
			t.Errorf("set on an unknown UUID no longer creates the entry: %v", g)
		}
	})

	t.Run("a GET with a Content-Type is rejected", func(t *testing.T) {
		if code, v := r.do("GET", p+"searchNeighbor", nil, true); code != 400 {
			t.Errorf("want HTTP 400, got %d %v", code, v)
		}
	})

	t.Run("search with rowCount -1 answers every row with a total", func(t *testing.T) {
		var ids []string
		for _, a := range []string{"192.0.2.31", "192.0.2.32"} {
			_, v := r.do("POST", p+"addNeighbor", map[string]any{"neighbor": map[string]any{"address": a}}, true)
			if id, _ := v.(map[string]any)["uuid"].(string); id != "" {
				ids = append(ids, id)
				defer cleanup(id)
			}
		}
		code, v := r.do("POST", p+"searchNeighbor", map[string]any{"rowCount": -1, "current": 1}, true)
		out, _ := v.(map[string]any)
		rows, _ := out["rows"].([]any)
		total, _ := out["total"].(float64)
		if code != 200 || len(rows) < len(ids) || int(total) != len(rows) {
			t.Errorf("HTTP %d: %d rows, total %v", code, len(rows), out["total"])
		}
	})

	t.Run("apply answers status ok", func(t *testing.T) {
		code, v := r.do("POST", "/api/quagga/service/reconfigure", nil, false)
		out, _ := v.(map[string]any)
		st, _ := out["status"].(string)
		if code != 200 || !strings.EqualFold(strings.TrimSpace(st), "ok") {
			t.Errorf("HTTP %d %v", code, v)
		}
	})
}

// body GETs path and returns the answer unparsed (status 200 required).
func (r *raw) body(path string) []byte {
	r.t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.base+path, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	req.SetBasicAuth(r.key, r.sec)
	resp, err := r.http.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		r.t.Fatalf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return b
}
