// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"os"
	"reflect"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Claim (README): Resources lists exactly what Entries and Settings bind
// on this firewall, with the same Info: a consumer that lists resources
// (an MCP server) cannot disagree with the client that writes them.
func TestResources(t *testing.T) {
	f := newFake(t)
	c := mustConnect(t, f)
	list := c.Resources()
	listed := map[string]Info{}
	for i, in := range list {
		if i > 0 && list[i-1].ID >= in.ID {
			t.Errorf("not sorted: %s before %s", list[i-1].ID, in.ID)
		}
		listed[in.ID] = in
	}
	n := 0
	for _, d := range c.Data().Docs {
		for id, r := range d.Resources {
			var info Info
			var err error
			if r.Kind == "entries" {
				var e *Entries
				if e, err = c.Entries(id); err == nil {
					info = e.Info()
				}
			} else {
				var s *Settings
				if s, err = c.Settings(id); err == nil {
					info = s.Info()
				}
			}
			got, ok := listed[id]
			switch {
			case err == nil && !ok:
				t.Errorf("%s binds but is not listed", id)
			case err != nil && ok:
				t.Errorf("%s is listed but does not bind: %v", id, err)
			case err == nil && !reflect.DeepEqual(got, info):
				t.Errorf("%s: listed %+v, bound %+v", id, got, info)
			}
			if err == nil {
				n++
			}
		}
	}
	if _, ok := listed[neighbors]; !ok || n != len(list) || n < 5 {
		t.Errorf("listed %d, bindable %d, neighbors listed: %v", len(list), n, ok)
	}
	f.plugins = map[string]string{} // os-frr not installed
	for _, in := range mustConnect(t, f).Resources() {
		if in.Package == "os-frr" {
			t.Errorf("%s of a plugin that is not installed is listed", in.ID)
		}
	}
}

// Claim (README): Schemas describes a resource over every version without
// a firewall: the union of its fields, the newest variant of each, and
// every change of a field's type between versions as an explicit
// conflict (os-frr's OSPF network area: a text field that became a
// relation; a route map's match2 that became a list).
func TestSchemas(t *testing.T) {
	s, err := capability.Load(os.DirFS("capability/testdata/catalog")) // private copy
	if err != nil {
		t.Fatal(err)
	}
	// one older variant of a field becomes write-only: the union hides it
	for _, v := range s.Docs["os-frr"].Resources[neighbors].Fields["description"] {
		v.WriteOnly = true
		break
	}
	list, err := Schemas(s)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Schema{}
	for _, x := range list {
		by[x.ID] = x
	}
	nw := by["quagga/ospfsettings#networks.network"]
	if nw.Kind != "entries" || !reflect.DeepEqual(nw.Packages, []string{"os-frr"}) {
		t.Errorf("networks: %+v", nw)
	}
	conflict := func(sc Schema, field string) *Conflict {
		for i := range sc.Conflicts {
			if sc.Conflicts[i].Field == field {
				return &sc.Conflicts[i]
			}
		}
		return nil
	}
	area := conflict(nw, "area")
	if area == nil || len(area.Variants) < 2 || area.Variants[0].Type != "TextField" ||
		area.Variants[len(area.Variants)-1].Type != "ModelRelationField" || nw.Fields["area"].Type != "ModelRelationField" {
		t.Errorf("area: conflict %+v, field %+v", area, nw.Fields["area"])
	}
	if v := area.Variants[0].Versions; len(v) == 0 || v[0] != "os-frr 1.45" {
		t.Errorf("area: versions of the oldest variant: %v", v)
	}
	rm := by["quagga/ospfsettings#routemaps.routemap"]
	m2 := conflict(rm, "match2")
	if m2 == nil || rm.Fields["match2"].Kind != capability.KindList || m2.Variants[0].Kind != capability.KindString {
		t.Errorf("match2: conflict %+v, field %+v", m2, rm.Fields["match2"])
	}
	nb := by[neighbors]
	if conflict(nb, "address") != nil || !nb.Fields["description"].WriteOnly || !nb.Fields["description"].Secret {
		t.Errorf("neighbors: %+v", nb)
	}
	if _, ok := by["quagga/ospfsettings"]; !ok {
		t.Error("settings missing")
	}
	s.Docs["os-frr"].Resources[neighbors].API = nil
	if _, err := Schemas(s); err == nil {
		t.Error("data that fails Check must be refused")
	}
}
