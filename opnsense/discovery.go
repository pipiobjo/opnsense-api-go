// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Resources describes every resource this firewall has, in its version,
// sorted by ID: what Entries and Settings would bind, with the same
// availability and read-only rules. For a server that lists what it can
// manage (an MCP server's list_resources).
func (c *Client) Resources() []Info {
	ids := make([]string, 0, len(c.owns))
	for id := range c.owns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Info
	for _, id := range ids {
		b, err := c.bind(id, "entries")
		var wk *ErrWrongKind
		if errors.As(err, &wk) {
			b, err = c.bind(id, "settings")
		}
		if err == nil {
			out = append(out, b.info())
		}
	}
	return out
}

// Schema describes a resource over every version in the capability data,
// without a firewall: what a provider needs for its schema before it is
// configured. Fields is the union of the fields of all versions; where a
// field's variants differ in type, kind or list-ness the FieldInfo is the
// newest variant's and Conflicts lists all of them, so the consumer
// decides instead of a silent pick. Secret and WriteOnly are true if any
// variant has them.
type Schema struct {
	ID        string
	Kind      string   // "settings" or "entries"
	Packages  []string // packages that define it, e.g. ["os-frr"]
	Fields    map[string]FieldInfo
	Conflicts []Conflict
}

// Conflict: the variants of one field differ in a way that changes how a
// value is typed.
type Conflict struct {
	Field    string
	Variants []Variant // oldest first
}

// Variant is one description of a field in some versions.
type Variant struct {
	Type     string // OPNsense field type, e.g. "TextField"
	Kind     capability.Kind
	Multiple bool
	Versions []string // "<package> <version>", e.g. "os-frr 1.40"
}

// Schemas describes every resource in the data over all its versions,
// sorted by ID (see Schema). It needs no connection.
func Schemas(data *capability.Set) ([]Schema, error) {
	if err := data.Check(); err != nil {
		return nil, fmt.Errorf("opnsense: capability data: %w", err)
	}
	type variant struct {
		v      Variant
		f      *capability.Field
		order  int // newest fragment the variant covers
		oldest int
	}
	byID := map[string]*Schema{}
	vars := map[string]map[string][]*variant{} // id -> field -> variants
	pkgs := make([]string, 0, len(data.Docs))
	for p := range data.Docs {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		d := data.Docs[pkg]
		for id, r := range d.Resources {
			s := byID[id]
			if s == nil {
				s = &Schema{ID: id, Kind: r.Kind, Fields: map[string]FieldInfo{}}
				byID[id] = s
				vars[id] = map[string][]*variant{}
			}
			if s.Kind != r.Kind {
				return nil, fmt.Errorf("opnsense: %s is %s in one package and %s in %s", id, s.Kind, r.Kind, pkg)
			}
			s.Packages = append(s.Packages, pkg)
			for name, fvs := range r.Fields {
				for _, f := range fvs {
					x := &variant{f: f, order: -1, oldest: int(^uint(0) >> 1),
						v: Variant{Type: f.Type, Kind: f.Kind(), Multiple: f.Multiple}}
					seen := map[string]bool{}
					var versions []string
					for _, h := range r.In {
						if !f.In.Has(h) {
							continue
						}
						fi := d.Fragments[h]
						x.order, x.oldest = max(x.order, fi.Order), min(x.oldest, fi.Order)
						for _, v := range fi.Versions {
							if !seen[v] {
								seen[v] = true
								versions = append(versions, v)
							}
						}
					}
					if x.order < 0 {
						continue // a variant of no fragment of the resource
					}
					sort.Slice(versions, func(i, j int) bool { return capability.CompareVersions(versions[i], versions[j]) < 0 })
					for _, v := range versions {
						x.v.Versions = append(x.v.Versions, pkg+" "+v)
					}
					vars[id][name] = append(vars[id][name], x)
				}
			}
		}
	}
	out := make([]Schema, 0, len(byID))
	for id, s := range byID {
		for name, vs := range vars[id] {
			sort.SliceStable(vs, func(i, j int) bool { return vs[i].oldest < vs[j].oldest })
			newest := vs[0]
			for _, x := range vs {
				if x.order > newest.order {
					newest = x
				}
			}
			fi := fieldInfo(name, newest.f, nil)
			var distinct []Variant
			for _, x := range vs {
				fi.Secret = fi.Secret || x.f.Secret(name)
				fi.WriteOnly = fi.WriteOnly || x.f.WriteOnly
				if !slices.ContainsFunc(distinct, func(v Variant) bool {
					return v.Type == x.v.Type && v.Kind == x.v.Kind && v.Multiple == x.v.Multiple
				}) {
					distinct = append(distinct, x.v)
				}
			}
			s.Fields[name] = fi
			if len(distinct) > 1 {
				var all []Variant
				for _, x := range vs {
					all = append(all, x.v)
				}
				s.Conflicts = append(s.Conflicts, Conflict{Field: name, Variants: all})
			}
		}
		sort.Slice(s.Conflicts, func(i, j int) bool { return s.Conflicts[i].Field < s.Conflicts[j].Field })
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
