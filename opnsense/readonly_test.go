// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"
)

// Claim K9: in read-only mode nothing that changes the firewall is sent.
// Every changing method is refused with *ErrReadOnly (errors.Is
// ErrWriteRefused); reads keep working; the only requests that reach the
// firewall are GETs and the search POST; its state is unchanged.
func TestReadOnlyMode(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	w := mustConnect(t, f) // a writing client sets up one entry
	wn, _ := w.Entries(neighbors)
	id, err := wn.Add(ctx, Values{"address": "192.0.2.10", "description": "lab"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	nbrs, ospf, applied := cloneNbrs(f.nbrs), maps.Clone(f.ospf), f.applied
	f.calls = nil
	f.mu.Unlock()

	c, err := connect(t, f, func(c *Config) {
		c.ReadOnly = true
		c.ReadOnlyAllow = []string{"/api/quagga/service/status", "/api/diagnostics/log/*"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Instance().ReadOnly {
		t.Error("Instance().ReadOnly not set")
	}
	n, _ := c.Entries(neighbors)
	s, _ := c.Settings("quagga/ospfsettings")

	// reads work
	if ids, err := n.List(ctx); err != nil || len(ids) != 1 {
		t.Errorf("List: %v %v", ids, err)
	}
	if v, err := n.Get(ctx, id); err != nil || v["address"] != "192.0.2.10" {
		t.Errorf("Get: %v %v", v, err)
	}
	if _, err := n.GetRaw(ctx, id); err != nil {
		t.Errorf("GetRaw: %v", err)
	}
	if _, err := s.Get(ctx); err != nil {
		t.Errorf("settings Get: %v", err)
	}
	var out any
	for _, p := range []string{"/api/quagga/ospfsettings/getNeighbor/" + id, "/api/quagga/ospfsettings/searchNeighbor"} {
		if err := c.Call(ctx, http.MethodGet, p, nil, &out); err != nil {
			t.Errorf("Call GET %s (a get or search operation): %v", p, err)
		}
	}
	// allowed by ReadOnlyAllow: the request is sent (the fake answers 404)
	for _, p := range []string{"/api/quagga/service/status", "/api/diagnostics/log/core/system"} {
		if err := c.Call(ctx, http.MethodGet, p, nil, &out); errors.Is(err, ErrWriteRefused) {
			t.Errorf("Call GET %s is in ReadOnlyAllow but was refused: %v", p, err)
		}
	}

	// every change is refused, typed
	refused := map[string]error{}
	_, refused["Add"] = n.Add(ctx, Values{"address": "192.0.2.11"})
	refused["Set"] = n.Set(ctx, id, Values{"description": "changed"})
	refused["Toggle"] = n.Toggle(ctx, id, false)
	refused["Delete"] = n.Delete(ctx, id)
	refused["Settings.Set"] = s.Set(ctx, Values{"routerid": "192.0.2.1"})
	refused["Client.Apply"] = c.Apply(ctx)
	refused["Entries.Apply"] = n.Apply(ctx)
	refused["Settings.Apply"] = s.Apply(ctx)
	refused["Call POST"] = c.Call(ctx, http.MethodPost, "/api/quagga/ospfsettings/addNeighbor", map[string]any{}, &out)
	refused["Call POST search"] = c.Call(ctx, http.MethodPost, "/api/quagga/ospfsettings/searchNeighbor", map[string]any{}, &out)
	refused["Call GET action"] = c.Call(ctx, http.MethodGet, "/api/quagga/service/reconfigure", nil, &out)
	refused["Call GET not listed"] = c.Call(ctx, http.MethodGet, "/api/core/system/reboot", nil, &out)
	for name, err := range refused {
		var ro *ErrReadOnly
		if !errors.As(err, &ro) || !ro.Mode || !errors.Is(err, ErrWriteRefused) {
			t.Errorf("%s: %v, want *ErrReadOnly in read-only mode", name, err)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if !strings.HasPrefix(call, "GET ") && call != "POST /api/quagga/ospfsettings/searchNeighbor" {
			t.Errorf("a request other than a read reached the firewall: %s", call)
		}
	}
	if !maps.EqualFunc(nbrs, f.nbrs, maps.Equal) || !maps.Equal(ospf, f.ospf) || f.applied != applied {
		t.Error("the firewall's state changed in read-only mode")
	}
}

func cloneNbrs(m map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(m))
	for k, v := range m {
		out[k] = maps.Clone(v)
	}
	return out
}

func TestReadOnlyConfig(t *testing.T) {
	f := newFake(t)
	if _, err := connect(t, f, func(c *Config) { c.ReadOnly, c.AutoApply = true, true }); err == nil {
		t.Error("ReadOnly with AutoApply must be refused")
	}
	if _, err := connect(t, f, func(c *Config) { c.ReadOnly, c.ReadOnlyAllow = true, []string{"/api/../core"} }); err == nil {
		t.Error("an invalid ReadOnlyAllow path must be refused")
	}
	c := mustConnect(t, f)
	if c.Instance().ReadOnly {
		t.Error("ReadOnly is off by default")
	}
}
