// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
)

// anyNameFS answers every name ("*" for all others), without the path
// validation real file systems do.
type anyNameFS map[string][]byte

func (a anyNameFS) Open(name string) (fs.File, error) {
	b, ok := a[name]
	if !ok {
		b = a["*"]
	}
	return fstest.MapFS{"f": {Data: b}}.Open("f")
}

// allFields: every field variant of the test data, in a stable order. The
// fuzz targets work on these generic field types, so a new OPNsense
// release (new data) needs no change here.
func allFields(t testing.TB) []*Field {
	s, err := Load(os.DirFS("testdata/catalog"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	byKey := map[string]*Field{}
	for pkg, d := range s.Docs {
		for id, r := range d.Resources {
			for name, vs := range r.Fields {
				for i, f := range vs {
					k := pkg + " " + id + " " + name + " " + string(rune('0'+i))
					keys = append(keys, k)
					byKey[k] = f
				}
			}
		}
	}
	sort.Strings(keys)
	out := make([]*Field, len(keys))
	for i, k := range keys {
		out[i] = byKey[k]
	}
	return out
}

// seedAnswers: the shapes OPNsense answers with, for one field: its
// default as a string, its options as a map with one selected, the same
// as a JSON list (PHP's encoding of keys 0..n), and plain numbers and
// booleans.
func seedAnswers(f *Field) [][]byte {
	var out [][]byte
	add := func(v any) {
		b, _ := json.Marshal(v)
		out = append(out, b)
	}
	if f.Default != nil {
		add(*f.Default)
	}
	if len(f.Options) > 0 {
		m := map[string]any{}
		var list []any
		for i, o := range f.Options {
			sel := 0
			if i == 0 {
				sel = 1
			}
			m[o.Value] = map[string]any{"value": o.Value, "selected": sel}
			list = append(list, map[string]any{"value": o.Value, "selected": sel})
		}
		add(m)
		add(list)
	}
	add("")
	add([]any{})
	add(1)
	add(true)
	return out
}

// FuzzWireDecode: any JSON answer for any field either fails cleanly or
// gives a wire value whose decoded Go value is stable under another
// encode and decode (what the client reads, it can write back unchanged).
func FuzzWireDecode(f *testing.F) {
	fields := allFields(f)
	for i, fd := range fields {
		for _, a := range seedAnswers(fd) {
			f.Add(a, uint(i))
		}
	}
	f.Fuzz(func(t *testing.T, answer []byte, idx uint) {
		fd := fields[idx%uint(len(fields))]
		dec := json.NewDecoder(bytes.NewReader(answer))
		dec.UseNumber() // as the client decodes answers
		var raw any
		if dec.Decode(&raw) != nil {
			return
		}
		wire, err := fd.Wire(raw)
		if err != nil {
			return
		}
		v, err := fd.Decode(wire)
		if err != nil {
			return
		}
		if v == nil {
			return // not set; nothing to write back
		}
		again, err := fd.Encode(v)
		if err != nil {
			return // e.g. a value outside a static option list: refused before sending
		}
		v2, err := fd.Decode(again)
		if err != nil || !reflect.DeepEqual(v, v2) {
			t.Fatalf("field %s: wire %q decodes to %#v, encodes to %q, decodes to %#v (%v)", fd.Type, wire, v, again, v2, err)
		}
	})
}

// FuzzLoad: a crafted catalog never crashes the loader, and a loaded set
// only names document files inside the data directory.
func FuzzLoad(f *testing.F) {
	cat, err := os.ReadFile("testdata/catalog/catalog.json")
	if err != nil {
		f.Fatal(err)
	}
	core, err := os.ReadFile("testdata/catalog/capabilities/opnsense.json")
	if err != nil {
		f.Fatal(err)
	}
	frr, err := os.ReadFile("testdata/catalog/capabilities/os-frr.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(cat, core)
	// the real catalog with the core's document moved outside the directory:
	// everything else is valid, so only the path check can refuse it
	for _, bad := range []string{"../opnsense.json", "../../etc/opnsense.json", "/opnsense.json", "capabilities/../../opnsense.json"} {
		var c map[string]any
		if err := json.Unmarshal(cat, &c); err != nil {
			f.Fatal(err)
		}
		c["packages"].(map[string]any)["opnsense"].(map[string]any)["file"] = bad
		b, _ := json.Marshal(c)
		f.Add(b, core)
	}
	f.Fuzz(func(t *testing.T, catalog, doc []byte) {
		// serves any name, also "../x" or "/x": only the client's own
		// check stands between a crafted catalog and a file outside
		fsys := anyNameFS{"catalog.json": catalog, "capabilities/os-frr.json": frr, "*": doc}
		s, err := Load(fsys)
		if err != nil {
			return
		}
		for name, p := range s.Catalog.Packages {
			if !fs.ValidPath(p.File) {
				t.Fatalf("package %s loaded from a path outside the directory: %q", name, p.File)
			}
		}
	})
}
