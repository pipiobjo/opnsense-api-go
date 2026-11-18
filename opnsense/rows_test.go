// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// searches counts the search requests the fake received since index from.
func (f *fakeFirewall) searches(from int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls[from:] {
		if strings.Contains(c, "/search") {
			n++
		}
	}
	return n
}

// Claim (K5, cost): where get answers an unknown ID with [] (most
// controllers, measured once per entry list and client), Get, Set, Toggle
// and the confirmation of Delete decide existence with one read of the
// entry, not with a search of the whole list; an unknown ID is still
// refused, and Set does not create it.
func TestExistenceWithoutASearch(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	from := len(f.calls)
	if _, err := n.Get(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := n.Set(ctx, id, Values{"description": "x"}); err != nil {
		t.Fatal(err)
	}
	if err := n.Toggle(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if err := n.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if s := f.searches(from); s != 0 {
		t.Errorf("%d searches for get, set, toggle and delete of one entry; want 0", s)
	}
	ghost := "00000000-0000-4000-8000-000000000099"
	if err := n.Set(ctx, ghost, Values{"address": "192.0.2.1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("set of an unknown ID: %v", err)
	}
	if err := n.Toggle(ctx, ghost, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("toggle of an unknown ID: %v", err)
	}
	if _, err := n.Get(ctx, ghost); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of an unknown ID: %v", err)
	}
	if len(f.nbrs) != 0 {
		t.Errorf("entries created: %v", f.nbrs)
	}
	probes := 0
	for _, call := range f.calls {
		if strings.HasSuffix(call, "/"+probeID) {
			probes++
		}
	}
	if probes != 1 {
		t.Errorf("%d probes of how get answers an unknown ID; want 1 per entry list and client", probes)
	}
}

// Claim: Rows returns every entry with its fields decoded as Get decodes
// them, from one search; display texts ("%enabled") are not fields; a
// field with an odd shape is reported per entry, the rest still returned.
func TestRows(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	a, _ := n.Add(ctx, Values{"address": "192.0.2.10", "priority": int64(7), "description": "a"})
	b, _ := n.Add(ctx, Values{"address": "192.0.2.11", "enabled": false})
	from := len(f.calls)
	rows, err := n.Rows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls)-from != 1 {
		t.Errorf("%d requests; want one search", len(f.calls)-from)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if len(rows) != 2 || rows[0].ID != a || rows[1].ID != b {
		t.Fatalf("rows: %+v", rows)
	}
	for _, r := range rows {
		got, err := n.Get(ctx, r.ID)
		if err != nil || !reflect.DeepEqual(r.Values, got) {
			t.Errorf("row %s: %#v, get: %#v %v", r.ID, r.Values, got, err)
		}
	}
	if rows[0].Values["priority"] != int64(7) || rows[1].Values["enabled"] != false {
		t.Errorf("decoded: %#v", rows)
	}
	f.oddField = "priority"
	rows, err = n.Rows(ctx)
	var de *ErrDecode
	if !errors.As(err, &de) || de.Fields[a+" priority"] == "" || de.Fields[b+" priority"] == "" || len(rows) != 2 {
		t.Fatalf("odd field: %v, rows %d", err, len(rows))
	}
	if _, has := rows[0].Values["priority"]; has || rows[0].Values["address"] == nil {
		t.Errorf("the odd field must be left out, the others kept: %#v", rows[0].Values)
	}
}

// Claim: Find returns exactly the entries whose fields equal every given
// value, compared as stored (the value encoded as Add sends it), in one
// search; where the search does not show a field, the entry is read. What
// cannot be compared is refused before anything is sent.
func TestFind(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	a, _ := n.Add(ctx, Values{"address": "192.0.2.10", "description": "x"})
	b, _ := n.Add(ctx, Values{"address": "192.0.2.11", "description": "x", "priority": int64(7)})
	ids := func(rows []Row) []string {
		out := []string{}
		for _, r := range rows {
			out = append(out, r.ID)
		}
		sort.Strings(out)
		return out
	}
	for _, tc := range []struct {
		match Values
		want  []string
	}{
		{Values{"description": "x"}, []string{a, b}},
		{Values{"description": "x", "address": "192.0.2.11"}, []string{b}},
		{Values{"priority": int64(7)}, []string{b}},
		{Values{"enabled": true, "address": "192.0.2.10"}, []string{a}},
		{Values{"address": "192.0.2.12"}, []string{}},
		{Values{}, []string{a, b}},
	} {
		from := len(f.calls)
		rows, err := n.Find(ctx, tc.match)
		if err != nil || !reflect.DeepEqual(ids(rows), tc.want) {
			t.Errorf("find %v: %v %v, want %v", tc.match, ids(rows), err, tc.want)
		}
		if len(f.calls)-from != 1 {
			t.Errorf("find %v: %d requests, want one search", tc.match, len(f.calls)-from)
		}
	}
	// a controller whose search shows only some columns: the entry is read
	f.searchColumns = []string{"address"}
	if rows, err := n.Find(ctx, Values{"priority": int64(7)}); err != nil || !reflect.DeepEqual(ids(rows), []string{b}) {
		t.Errorf("field not in the search: %v %v", ids(rows), err)
	}
	// rows the search adds without a stored entry (26.1 d_nat anti-lockout
	// rules) and without the field: get does not know them, so no match
	f.virtualRows = []string{"lockout_0"}
	if rows, err := n.Find(ctx, Values{"priority": int64(7)}); err != nil || !reflect.DeepEqual(ids(rows), []string{b}) {
		t.Errorf("uncounted rows without the field: %v %v", ids(rows), err)
	}
	f.virtualRows = nil
	f.searchColumns = nil
	var na *ErrFieldNotAvailable
	if _, err := n.Find(ctx, Values{"bogus": "x"}); !errors.As(err, &na) {
		t.Errorf("unknown field: %v", err)
	}
	var inv *ErrInvalid
	from := len(f.calls)
	if _, err := n.Find(ctx, Values{"priority": "seven"}); !errors.As(err, &inv) {
		t.Errorf("value that could not be sent: %v", err)
	}
	if len(f.calls) != from {
		t.Errorf("a refused Find sent %d requests", len(f.calls)-from)
	}
}

// Claim: when reading the probe ID fails (an error, not an answer), the
// client does not trust get and asks the search, and it measures again
// next time instead of keeping a result it never got.
func TestProbeErrorLeavesItToTheSearch(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.fullTemplate = true // unknown IDs read as a template
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	orig := f.srv.Config.Handler
	probes := 0
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/"+probeID) {
			probes++
			w.WriteHeader(http.StatusNotFound) // an error, not an answer
			return
		}
		orig.ServeHTTP(w, r)
	})
	ghost := "00000000-0000-4000-8000-000000000099"
	if _, err := n.Get(ctx, ghost); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of an unknown ID after a failed probe: %v", err)
	}
	if err := n.Set(ctx, ghost, Values{"address": "192.0.2.1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("set of an unknown ID after a failed probe: %v", err)
	}
	if probes != 2 {
		t.Errorf("%d probes; a failed probe must be repeated (want 2)", probes)
	}
}

// withField returns a copy of the entry list's API and resource in which
// mod changed the operations and the field name (private copies, so other
// tests keep the shared data).
func withField(t *testing.T, n *Entries, name string, mod func(api *capability.API, f *capability.Field)) {
	t.Helper()
	api := *n.b.api
	api.Operations = map[string]*capability.Operation{}
	for k, v := range n.b.api.Operations {
		op := *v
		api.Operations[k] = &op
	}
	res := *n.b.res
	res.Fields = map[string][]*capability.Field{}
	for k, v := range n.b.res.Fields {
		res.Fields[k] = v
	}
	f := *n.b.res.FieldFor(name, n.b.frag)
	f.In = capability.In{All: true}
	res.Fields[name] = []*capability.Field{&f}
	mod(&api, &f)
	n.b.api, n.b.res = &api, &res
}

// Claim: Rows and Find do not trust the search for a field whose stored
// form differs from what get shows, as the data marks it: a field the
// add or set operation stores transformed (os-nginx error page content)
// is left out of Rows and refused by Find; a field whose type renders a
// string with its own read code (custom-read-shape, JsonAuditField) is
// left out of Rows and compared through Get by Find.
func TestRowsOnlyWhatTheSearchShowsAsGetDoes(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, _ := n.Add(ctx, Values{"address": "192.0.2.10", "description": "x", "priority": int64(7)})
	f.searchRaw = map[string]string{"description": "eA==", "priority": "999"}
	withField(t, n, "description", func(api *capability.API, _ *capability.Field) {
		api.Operations["set"].Transformed = []string{"description"}
	})
	withField(t, n, "priority", func(_ *capability.API, fd *capability.Field) {
		fd.Gaps, fd.ReadShape = []string{capability.GapCustomReadShape}, "string"
	})
	rows, err := n.Rows(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %v", rows, err)
	}
	for _, name := range []string{"description", "priority"} {
		if v, has := rows[0].Values[name]; has {
			t.Errorf("rows show %s = %#v; the search does not show it as get does", name, v)
		}
	}
	if rows[0].Values["address"] != "192.0.2.10" {
		t.Errorf("other fields must stay: %#v", rows[0].Values)
	}
	var inv *ErrInvalid
	if _, err := n.Find(ctx, Values{"description": "x"}); !errors.As(err, &inv) {
		t.Errorf("find by a transformed field: %v", err)
	}
	found, err := n.Find(ctx, Values{"priority": int64(7)})
	if err != nil || len(found) != 1 || found[0].ID != id {
		t.Errorf("find by a field rendered by its type, through get: %v %v", found, err)
	}
}

// Claim: an answer get cannot read for an ID (an error, or no outer key)
// does not end the existence check: the search decides, so a delete is
// confirmed and an unknown ID is ErrNotFound, not an error.
func TestUnreadableGetLeavesItToTheSearch(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, _ := n.Add(ctx, Values{"address": "192.0.2.10"})
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/quagga/ospfsettings/getNeighbor/") {
			f.mu.Lock()
			missing := f.nbrs[strings.TrimPrefix(r.URL.Path, "/api/quagga/ospfsettings/getNeighbor/")] == nil
			f.mu.Unlock()
			if missing {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		orig.ServeHTTP(w, r)
	})
	if err := n.Delete(ctx, id); err != nil {
		t.Errorf("delete: %v", err)
	}
	if err := n.Set(ctx, id, Values{"address": "192.0.2.11"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("set of a deleted ID: %v", err)
	}
	if _, err := n.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of a deleted ID: %v", err)
	}
}

// Claim: an option or relation field (read shape "select") stays in Rows
// although its type has its own read code: get renders the same stored
// value as a map, which decoding turns back into that value (checked on
// the VM by comparing Rows with Get on every verified entry list).
func TestRowsKeepSelectFields(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	_, _ = n.Add(ctx, Values{"address": "192.0.2.10", "priority": int64(7)})
	withField(t, n, "priority", func(_ *capability.API, fd *capability.Field) {
		fd.Gaps, fd.ReadShape = []string{capability.GapCustomReadShape}, "select"
	})
	rows, err := n.Rows(ctx)
	if err != nil || len(rows) != 1 || rows[0].Values["priority"] == nil {
		t.Errorf("a select field must stay in the rows: %v %v", rows, err)
	}
}
