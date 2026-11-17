// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"maps"
	"slices"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// FieldInfo describes one field of a resource in the firewall's version:
// what a consumer needs to model it (a provider schema, a form), as a value
// that is safe to keep and change. It is derived from the capability data.
type FieldInfo struct {
	Name string // field path, e.g. "hostname" or "general.enabled"
	Type string // OPNsense field type, e.g. "HostnameField"
	Kind capability.Kind
	// Multiple: a list field (Values carry []string).
	Multiple bool
	// Required: the model marks the field as required. The firewall may
	// fill some required fields itself on add.
	Required bool
	// RuntimeRequired: the contract test found the firewall requiring this
	// field although the model does not mark it (for example the server of
	// an Unbound host override). Treat it as required for a write.
	RuntimeRequired bool
	// ServerSet: the firewall sets the value itself; it cannot be written.
	ServerSet bool
	// WriteOnly: stored but never returned (passwords). A read never has
	// it, and a change made elsewhere cannot be seen.
	WriteOnly bool
	// Volatile: not stored; it cannot be managed.
	Volatile bool
	// CustomWrite: the field's type converts values on write, so a value
	// may read back in another form.
	CustomWrite bool
	Default     *string // the model's default, nil if none
	// Options: the static options; StaticOptions says whether they are the
	// complete list (otherwise the firewall may accept more).
	Options       []capability.Option
	StaticOptions bool
	Relations     []capability.Relation // entry lists a relation field points to
	Gaps          []string              // what the data could not derive about the field
}

// Info describes a resource in the firewall's version.
type Info struct {
	ID      string
	Kind    string // "settings" or "entries"
	Package string // the package that provides it, e.g. "core" or "os-frr"
	Version string // its installed version
	// SharedWith: other resources that address the same stored data. Manage
	// such data through one of them only; two owners overwrite each other.
	SharedWith []string
	// ReadOnly: why writes are refused ("" if they are allowed).
	ReadOnly string
	// Verified: the contract test result for this version, nil if this
	// version was not tested. Show it to users: an untested resource may
	// behave differently from its description.
	Verified *capability.ResVerify
	Fields   map[string]FieldInfo
}

// Info describes the entry list in the firewall's version.
func (e *Entries) Info() Info { return e.b.info() }

// Info describes the settings resource in the firewall's version.
func (s *Settings) Info() Info { return s.b.info() }

func (b *bound) info() Info {
	in := Info{ID: b.id, Kind: b.res.Kind, Package: b.pkg, Version: b.version,
		SharedWith: slices.Clone(b.res.SharedWith), ReadOnly: b.readOnly, Fields: map[string]FieldInfo{}}
	if b.c.cfg.ReadOnly {
		in.ReadOnly = readOnlyModeReason
	}
	var runtime []string
	if b.verified != nil {
		v := *b.verified
		v.Steps = slices.Clone(v.Steps)
		v.Generated = slices.Clone(v.Generated)
		v.RuntimeRequired = slices.Clone(v.RuntimeRequired)
		v.Findings = slices.Clone(v.Findings)
		v.Sample = maps.Clone(v.Sample)
		in.Verified = &v
		runtime = v.RuntimeRequired
	}
	for name, f := range b.res.FieldsFor(b.frag) {
		c := f.Clone()
		in.Fields[name] = FieldInfo{Name: name, Type: c.Type, Kind: c.Kind(), Multiple: c.Multiple,
			Required: c.Required, RuntimeRequired: slices.Contains(runtime, name),
			ServerSet: c.ServerSet, WriteOnly: c.WriteOnly, Volatile: c.Volatile, CustomWrite: c.CustomWrite(),
			Default: c.Default, Options: c.Options, StaticOptions: c.StaticOptions(), Relations: c.Relations, Gaps: c.Gaps}
	}
	return in
}

// Check runs every check a write would run, without sending anything: the
// fields exist in this version, the values fit their types and options, no
// field is set by the firewall, and writes are allowed. For an entry list
// the values are checked for both add and set. Use it at plan time; the
// firewall's own validation (ErrValidation) still happens on write.
func (e *Entries) Check(v Values) error {
	b := e.b
	if err := b.writable(); err != nil {
		return err
	}
	checked := false
	for _, name := range []string{"add", "set"} {
		if op := b.api.Operations[name]; op != nil {
			checked = true
			if _, _, err := b.encode(v, op); err != nil {
				return err
			}
		}
	}
	if !checked {
		_, err := b.op("add")
		return err
	}
	return nil
}

// Check runs every check Set would run, without sending anything (see
// Entries.Check).
func (s *Settings) Check(v Values) error {
	b := s.b
	if err := b.writable(); err != nil {
		return err
	}
	op, err := b.op("set")
	if err != nil {
		return err
	}
	_, _, err = b.encode(v, op)
	return err
}

func cloneFields(m map[string]*capability.Field) map[string]*capability.Field {
	out := make(map[string]*capability.Field, len(m))
	for k, f := range m {
		out[k] = f.Clone()
	}
	return out
}
