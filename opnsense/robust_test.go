// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Entry IDs that are not UUIDs never reach the firewall: no path tricks,
// no empty ID that would address the blank template.
func TestBadIDsAreRefused(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	before := len(f.calls)
	for _, id := range []string{"", "..", ".", ".hidden", "a/b", "../../core/firmware/poweroff", "00000000-0000-4000-8000-00000000000%", " 00000000-0000-4000-8000-000000000001", "a?b", strings.Repeat("a", 129)} {
		if _, err := n.Get(ctx, id); !errors.Is(err, ErrBadID) {
			t.Errorf("Get(%q): %v", id, err)
		}
		if err := n.Set(ctx, id, Values{"description": "x"}); !errors.Is(err, ErrBadID) {
			t.Errorf("Set(%q): %v", id, err)
		}
		if err := n.Delete(ctx, id); !errors.Is(err, ErrBadID) {
			t.Errorf("Delete(%q): %v", id, err)
		}
		if err := n.Toggle(ctx, id, true); !errors.Is(err, ErrBadID) {
			t.Errorf("Toggle(%q): %v", id, err)
		}
	}
	if len(f.calls) != before {
		t.Errorf("requests were sent: %v", f.calls[before:])
	}
}

// A write that is saved while an apply runs must stay pending.
func TestApplyKeepsWritesDuringTheCall(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	s, _ := c.Settings("quagga/ospfsettings")
	if err := s.Set(ctx, Values{"enabled": true}); err != nil {
		t.Fatal(err)
	}
	f.applyGate, f.applyStart = make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	var applyErr error
	wg.Add(1)
	go func() { defer wg.Done(); applyErr = c.Apply(ctx) }()
	<-f.applyStart // reconfigure is running
	if err := s.Set(ctx, Values{"costreference": int64(100)}); err != nil {
		t.Fatal(err)
	}
	close(f.applyGate)
	wg.Wait()
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if p := c.Pending(); len(p) != 1 {
		t.Fatalf("the write during the apply was dropped: pending %v", p)
	}
	f.applyGate = nil
	if err := s.Apply(ctx); err != nil || len(c.Pending()) != 0 || f.applied != 2 {
		t.Errorf("second apply: %v, pending %v, applied %d", err, c.Pending(), f.applied)
	}
}

func TestApplyNeedsAnExplicitOK(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []map[string]any{{"status": "failed"}, {}, {"result": "saved"}, {"status": "Error (1)"}} {
		f := newFake(t)
		f.applyAnswer = answer
		c := mustConnect(t, f)
		s, _ := c.Settings("quagga/ospfsettings")
		_ = s.Set(ctx, Values{"enabled": true})
		var ae *ErrApply
		if err := c.Apply(ctx); !errors.As(err, &ae) {
			t.Errorf("apply answer %v: %v", answer, err)
		}
		if len(c.Pending()) != 1 {
			t.Errorf("a failed apply must stay pending (answer %v)", answer)
		}
	}
}

func TestDetectionWithoutFirmwarePrivilege(t *testing.T) {
	f := newFake(t)
	f.infoStatus = http.StatusForbidden
	c := mustConnect(t, f)
	inst := c.Instance()
	if inst.Core != "26.7.9_1" || len(inst.Plugins) != 0 || !strings.Contains(strings.Join(inst.Warnings, "|"), "plugin list not available") {
		t.Errorf("fallback: %+v", inst)
	}
	if _, err := c.Entries(neighbors); err == nil {
		t.Error("without the plugin list, plugin resources are not available")
	}
	f2 := newFake(t)
	f2.infoStatus = http.StatusUnauthorized
	if _, err := connect(t, f2); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("401 must not fall back: %v", err)
	}
}

func TestOneOddFieldDoesNotHideTheOthers(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "x"})
	if err != nil {
		t.Fatal(err)
	}
	f.oddField = "priority"
	v, err := n.Get(ctx, id)
	var de *ErrDecode
	if !errors.As(err, &de) || de.Fields["priority"] == "" || v["description"] != "x" || v["address"] != "192.0.2.10" {
		t.Errorf("decode: %v %#v", err, v)
	}
	if _, has := v["priority"]; has {
		t.Error("the odd field must not be returned with a guessed value")
	}
}

func TestDeleteIsConfirmed(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, _ := n.Add(ctx, Values{"address": "192.0.2.10"})
	f.delKeeps = true
	if err := n.Delete(ctx, id); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Errorf("delete that did not delete: %v", err)
	}
}

func TestListPagesAndGetOnlySearch(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.searchPage = 1
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	for i := 0; i < 3; i++ {
		if _, err := n.Add(ctx, Values{"address": "192.0.2.1" + string(rune('0'+i))}); err != nil {
			t.Fatal(err)
		}
	}
	if ids, err := n.List(ctx); err != nil || len(ids) != 3 {
		t.Errorf("POST search with rowCount -1: %v %v", ids, err)
	}
	// the same resource as if search were GET-only: the query must arrive
	// as a query, not inside the path
	n.b.api = withSearchMethods(n.b.api, "GET")
	if ids, err := n.List(ctx); err != nil || len(ids) != 3 {
		t.Errorf("GET search: %v %v", ids, err)
	}
}

func withSearchMethods(a *capability.API, methods ...string) *capability.API {
	cp := *a
	cp.Operations = map[string]*capability.Operation{}
	for k, v := range a.Operations {
		op := *v
		cp.Operations[k] = &op
	}
	cp.Operations["search"].Methods = methods
	return &cp
}

func TestListNoticesMissingRows(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	for i := 0; i < 2; i++ {
		_, _ = n.Add(ctx, Values{"address": "192.0.2.2" + string(rune('0'+i))})
	}
	// a search that pages although rowCount -1 was asked for
	f.searchPage = 1
	n.b.api = withSearchMethods(n.b.api, "GET")
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.RawQuery = ""
		orig.ServeHTTP(w, r)
	})
	if _, err := n.List(ctx); err == nil || !strings.Contains(err.Error(), "of 2 rows") {
		t.Errorf("paged search must be an error: %v", err)
	}
}

func TestToggle(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, _ := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err := n.Toggle(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if f.nbrs[id]["enabled"] != "0" {
		t.Error("not disabled")
	}
	before := len(f.calls)
	if err := n.Toggle(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls[before:] {
		if strings.Contains(call, "toggle") {
			t.Error("toggling to the current state must not flip it")
		}
	}
	if err := n.Toggle(ctx, "00000000-0000-4000-8000-000000000099", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("toggle of a missing entry: %v", err)
	}
}

func TestInstanceIsACopy(t *testing.T) {
	c := mustConnect(t, newFake(t))
	in := c.Instance()
	in.Plugins["os-evil"] = "1.0"
	in.Resolved.Packages["os-frr"].Fragment = "x"
	in.Warnings = append(in.Warnings, "x")
	again := c.Instance()
	if again.Plugins["os-evil"] != "" || again.Resolved.Packages["os-frr"].Fragment == "x" || len(again.Warnings) != 0 {
		t.Error("Instance() exposes internal state")
	}
}

func TestBrokenDataIsAnErrorNotAPanic(t *testing.T) {
	f := newFake(t)
	broken := &capability.Set{Catalog: data(t).Catalog, Docs: map[string]*capability.Doc{
		capability.CorePackage: data(t).Docs[capability.CorePackage],
		"os-x":                 {Resources: map[string]*capability.Resource{"x/y": nil}},
	}}
	if _, err := connect(t, f, func(c *Config) { c.Capabilities = broken }); err == nil || !strings.Contains(err.Error(), "null resource") {
		t.Errorf("broken data: %v", err)
	}
}

func TestCall(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	var out map[string]any
	if err := c.Call(ctx, http.MethodPost, "/api/quagga/service/reconfigure", nil, &out); err != nil || out["status"] != "ok" {
		t.Errorf("call: %v %v", out, err)
	}
	if err := c.Call(ctx, http.MethodGet, "/api/../../etc", nil, &out); err == nil {
		t.Error("a path with .. must be refused")
	}
	if err := c.Call(ctx, http.MethodDelete, "/api/x/y", nil, &out); err == nil {
		t.Error("only GET and POST")
	}
}

func TestWriteOnlyFieldsAreNotDecoded(t *testing.T) {
	r := &capability.Resource{Kind: "entries", In: []string{"h"}, Fields: map[string][]*capability.Field{
		"password": {{In: capability.In{All: true}, Type: "UpdateOnlyTextField", Base: "UpdateOnlyTextField"}},
		"name":     {{In: capability.In{All: true}, Type: "TextField", Base: "TextField"}},
	}}
	b := &bound{id: "x/y#z", frag: "h", res: r}
	v, err := b.decode(map[string]any{"password": "", "name": "n"})
	if err != nil || v["name"] != "n" {
		t.Fatal(v, err)
	}
	if _, has := v["password"]; has {
		t.Error("a write-only field reads as empty and would look like drift")
	}
}

// IDs that are not UUIDs exist: interface names, alias names, hashes.
func TestNonUUIDIDsAreAccepted(t *testing.T) {
	for _, id := range []string{"wan", "opt1", "bogons", "0add3c58db981d0d24d5d4ab322e3695", "00000000-0000-4000-8000-000000000001", "a.b_c-d"} {
		if err := checkID(id); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}

// A plugin that answers an unknown UUID with a blank template (os-nginx):
// the list decides.
func TestBlankTemplateIsNotAnEntry(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/quagga/ospfsettings/getNeighbor/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/quagga/ospfsettings/getNeighbor/")
			f.mu.Lock()
			missing := f.nbrs[id] == nil
			f.mu.Unlock()
			if missing {
				w.Write([]byte(`{"neighbor":{"description":""}}`))
				return
			}
		}
		orig.ServeHTTP(w, r)
	})
	ghost := "00000000-0000-4000-8000-000000000099"
	if _, err := n.Get(ctx, ghost); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of a template: %v", err)
	}
	if err := n.Set(ctx, ghost, Values{"address": "192.0.2.1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("set must not create the entry: %v", err)
	}
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Delete(ctx, id); err != nil {
		t.Errorf("delete confirmed through the list despite the template: %v", err)
	}
}

func TestServerSetFieldsAndOptionLists(t *testing.T) {
	uid := &capability.Field{Type: "UniqueIdField", Base: "UniqueIdField"}
	audit := &capability.Field{Type: "JsonAuditField", Base: "JsonAuditField"}
	if !uid.ServerSet() || !audit.ServerSet() {
		t.Error("server-set fields")
	}
	r := &capability.Resource{Kind: "entries", In: []string{"h"}, Fields: map[string][]*capability.Field{
		"id":      {{In: capability.In{All: true}, Type: "UniqueIdField", Base: "UniqueIdField"}},
		"service": {{In: capability.In{All: true}, Type: "ServiceField", Base: "BaseListField", Options: []capability.Option{{Value: "a"}}}},
		"mode":    {{In: capability.In{All: true}, Type: "OptionField", Base: "BaseListField", Options: []capability.Option{{Value: "a"}}}},
	}}
	b := &bound{id: "x/y#z", frag: "h", res: r, c: &Client{}}
	add := &capability.Operation{Path: "/api/x/y/addZ", Forced: map[string]string{"mode": "a"}}
	plain := &capability.Operation{Path: "/api/x/y/setZ"}
	_, _, err := b.encode(Values{"id": "x"}, plain)
	var inv *ErrInvalid
	if !errors.As(err, &inv) || !strings.Contains(inv.Problems["id"], "set by the firewall") {
		t.Errorf("writing a server-set field: %v", err)
	}
	if _, _, err := b.encode(Values{"service": "added-at-run-time"}, plain); err != nil {
		t.Errorf("a subclass may have more options than the data lists: %v", err)
	}
	if _, _, err := b.encode(Values{"mode": "z"}, plain); !errors.As(err, &inv) {
		t.Errorf("an OptionField's list is complete: %v", err)
	}
	// an endpoint that overwrites a field: refused before sending
	if _, _, err := b.encode(Values{"mode": "a"}, add); !errors.As(err, &inv) || !strings.Contains(inv.Problems["mode"], "forced to") {
		t.Errorf("forced field: %v", err)
	}
	computed := &capability.Operation{Path: "/api/x/y/addZ", Computed: []string{"mode"}}
	if _, _, err := b.encode(Values{"mode": "a"}, computed); !errors.As(err, &inv) || !strings.Contains(inv.Problems["mode"], "computed by") {
		t.Errorf("computed field: %v", err)
	}
}

func TestApplyAcceptsResultOK(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.applyAnswer = map[string]any{"result": "ok"}
	c := mustConnect(t, f)
	s, _ := c.Settings("quagga/ospfsettings")
	_ = s.Set(ctx, Values{"enabled": true})
	if err := c.Apply(ctx); err != nil || len(c.Pending()) != 0 {
		t.Errorf("result ok: %v %v", err, c.Pending())
	}
}

// A delete endpoint that answers nothing (gap result-not-returned): only
// the existence check decides.
func TestSilentDelete(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, _ := n.Add(ctx, Values{"address": "192.0.2.10"})
	f.delSilent = true
	if err := n.Delete(ctx, id); err == nil {
		t.Error("an empty answer without the gap in the data must be an error")
	}
	id2, _ := n.Add(ctx, Values{"address": "192.0.2.11"})
	api := *n.b.api
	api.Operations = map[string]*capability.Operation{}
	for k, v := range n.b.api.Operations {
		op := *v
		api.Operations[k] = &op
	}
	api.Operations["del"].Gaps = []string{"result-not-returned"}
	n.b.api = &api
	if err := n.Delete(ctx, id2); err != nil {
		t.Errorf("silent delete with the gap: %v", err)
	}
	f.delKeeps = true
	id3, _ := n.Add(ctx, Values{"address": "192.0.2.12"})
	if err := n.Delete(ctx, id3); err == nil {
		t.Error("a silent delete that did not delete must be noticed")
	}
}

// A field the endpoint stores in another form (nginx base64-encodes error
// page content) is written, but not compared on read-back.
func TestTransformedFieldIsWrittenNotCompared(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	api := *n.b.api
	api.Operations = map[string]*capability.Operation{}
	for k, v := range n.b.api.Operations {
		op := *v
		api.Operations[k] = &op
	}
	api.Operations["add"].Transformed = []string{"description"}
	n.b.api = &api
	f.dropSets["description"] = true // stored differently: reads back as ""
	if _, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "x"}); err != nil {
		t.Errorf("transformed field compared on read-back: %v", err)
	}
	api.Operations["add"].Transformed = nil
	var na *ErrNotApplied
	if _, err := n.Add(ctx, Values{"address": "192.0.2.11", "description": "x"}); !errors.As(err, &na) {
		t.Errorf("without the mark the difference must be reported: %v", err)
	}
}

// More rows than the total is not an error: 26.1's firewall/d_nat search
// adds anti-lockout rules it does not count. The real entries can still
// be found, set and deleted.
func TestSearchWithUncountedRows(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.virtualRows = []string{"lockout_0", "lockout_1"}
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := n.List(ctx)
	if err != nil || len(ids) != 3 {
		t.Fatalf("list with uncounted rows: %v %v", ids, err)
	}
	if err := n.Set(ctx, id, Values{"description": "x"}); err != nil {
		t.Errorf("set: %v", err)
	}
	if err := n.Delete(ctx, id); err != nil {
		t.Errorf("delete: %v", err)
	}
}

// A write-only field (UpdateOnlyTextField, e.g. a password) is stored but
// always reads back as "". The read-back must skip it, or every write of
// a secret would fail as "not applied"; Get leaves it out.
func TestWriteOnlyFieldIsNotReadBack(t *testing.T) {
	ctx := context.Background()
	s, err := capability.Load(os.DirFS("capability/testdata/catalog")) // private copy
	if err != nil {
		t.Fatal(err)
	}
	const frag = "b04bde19061e2dec" // os-frr 2.1 in the test data
	fd := s.Docs["os-frr"].Resources[neighbors].FieldFor("description", frag)
	fd.Type, fd.Base = "UpdateOnlyTextField", "UpdateOnlyTextField"
	f := newFake(t)
	f.writeOnly = map[string]bool{"description": true}
	c, err := connect(t, f, func(cfg *Config) { cfg.Capabilities = s })
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "secret"})
	if err != nil {
		t.Fatalf("add with a write-only field: %v", err)
	}
	if err := n.Set(ctx, id, Values{"description": "secret2"}); err != nil {
		t.Errorf("set of a write-only field: %v", err)
	}
	got, err := n.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["description"]; ok {
		t.Errorf("get must leave a write-only field out: %v", got)
	}
	if f.nbrs[id]["description"] != "secret2" {
		t.Errorf("the value must still be sent and stored: %q", f.nbrs[id]["description"])
	}
}
