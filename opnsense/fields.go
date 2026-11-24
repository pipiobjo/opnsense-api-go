// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"errors"
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
	// WriteOnly: get returns it empty (passwords, API keys), so Get and
	// Rows never have it and a change made elsewhere cannot be seen. From
	// OPNsense 26.1.8 on a raw search answer contains the stored value (a
	// hash, the key blob); the client leaves it out of Rows.
	WriteOnly bool
	// Secret: the value must not be shown (plan output, logs, a tool's
	// answer): every write-only field, and free-text fields whose name
	// says password, secret, key, token, passphrase, community and the
	// like (capability.Field.Secret has the rule). It errs towards hiding.
	Secret bool
	// Volatile: not stored; it cannot be managed.
	Volatile bool
	// CustomWrite: the field's type converts values on write, so a value
	// may read back in another form.
	CustomWrite bool
	Default     *string // the model's default, nil if none
	// Options: the static options; StaticOptions says whether they are the
	// complete list (otherwise the firewall may accept more).
	Options       []Option
	StaticOptions bool
	Relations     []Relation // entry lists a relation field points to
	Gaps          []string   // what the data could not derive about the field
}

// Option is a static option of a field: the value to send, and how the
// firewall labels and groups it.
type Option struct{ Value, Label, Group string }

// Relation names an entry list a relation field points to: its model
// (Source, e.g. "OPNsense.Firewall.Alias") and the path of its entries
// (Items).
type Relation struct{ Source, Items string }

// VerifyStatus is a result of the contract test (Verification.Read and
// Write). Only VerifyOK is a pass.
type VerifyStatus = capability.Status

// Results of the contract test.
const (
	VerifyOK       = capability.StatusOK
	VerifyAccepted = capability.StatusAccepted // a failure declared expected upstream
	VerifySkipped  = capability.StatusSkipped  // not tested; Findings say why
	VerifyKnownGap = capability.StatusKnownGap // differs where the data already marks a gap
	VerifyMismatch = capability.StatusMismatch
	VerifyError    = capability.StatusError
)

// Verification is what the contract test of opnsense-api-spec found for a
// resource on a throwaway firewall, in the data that describes this
// firewall's version. Show it to users ("written and read back on 26.7.9",
// "not tested"): an untested resource may behave differently from its
// description. Use Info.WriteVerified to decide whether writing was tested.
type Verification struct {
	Release string // the release the test ran on, e.g. "26.7.9"
	Date    string // when, RFC 3339
	// Read: the reads (get, search) decoded as the data says. Write: an
	// entry was added, changed and deleted, or a settings field set and
	// restored, each read back; it covers the sample fields (entries) or
	// the one changed field (settings), not every field. VerifySkipped and
	// "" mean not written, never a pass.
	Read, Write     VerifyStatus
	Steps           []string // what was done, e.g. add, read-back, set, del
	Findings        []string // why a step did not pass
	RuntimeRequired []string // fields the firewall required although the model does not mark them
	// SameDefinition: this version's data was not tested itself; the result
	// is that of Release, whose description of the resource is identical
	// (same series).
	SameDefinition bool
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
	// Verified: the contract test result for the data that describes this
	// firewall's version: from this version, or from one with the same
	// description (Verification.SameDefinition); nil if none was tested.
	// Non-nil does not mean written: a result may be read-only, skipped or
	// a known gap; WriteVerified says whether writing was tested.
	Verified *Verification
	// Assumed: the firewall's version of the package is not in the data;
	// the data of the nearest version of the series is used (a warning in
	// Instance().Warnings), so Verified comes from another version.
	Assumed bool
	Fields  map[string]FieldInfo
}

// VerifiedOn names the release the contract test ran on for this
// resource, "" if it was not tested.
func (in Info) VerifiedOn() string {
	if in.Verified == nil {
		return ""
	}
	return in.Verified.Release
}

// WriteVerified reports whether writing this resource was tested on data
// that describes this firewall's version: read and write passed, the
// version is in the data (not Assumed), and for settings the test changed
// a value and restored it (older results only wrote the current value
// back, which an endpoint that stores nothing also passes). A provider
// warns for every resource where it is false.
func (in Info) WriteVerified() bool {
	v := in.Verified
	if v == nil || in.Assumed || v.Read != VerifyOK || v.Write != VerifyOK {
		return false
	}
	return in.Kind != "settings" || slices.Contains(v.Steps, capability.StepReadBackRestore)
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
	in.Verified, in.Assumed = verification(b.verified), b.assumed
	var runtime []string
	if in.Verified != nil {
		runtime = in.Verified.RuntimeRequired
	}
	for name, f := range b.res.FieldsFor(b.frag) {
		in.Fields[name] = fieldInfo(name, f, runtime)
	}
	return in
}

// fieldInfo describes one field variant, as copies.
func fieldInfo(name string, f *capability.Field, runtime []string) FieldInfo {
	c := f.Clone()
	fi := FieldInfo{Name: name, Type: c.Type, Kind: c.Kind(), Multiple: c.Multiple,
		Required: c.Required, RuntimeRequired: slices.Contains(runtime, name),
		ServerSet: c.ServerSet, WriteOnly: c.WriteOnly, Secret: c.Secret(name), Volatile: c.Volatile, CustomWrite: c.CustomWrite(),
		Default: c.Default, StaticOptions: c.StaticOptions(), Gaps: c.Gaps}
	for _, o := range c.Options {
		fi.Options = append(fi.Options, Option{Value: o.Value, Label: o.Label, Group: o.Group})
	}
	for _, r := range c.Relations {
		fi.Relations = append(fi.Relations, Relation{Source: r.Source, Items: r.Items})
	}
	return fi
}

// verification copies a result of the data into the client's own type.
func verification(v *capability.ResVerify) *Verification {
	if v == nil {
		return nil
	}
	return &Verification{Release: v.Release, Date: v.Date, Read: v.Read, Write: v.Write,
		Steps: slices.Clone(v.Steps), Findings: slices.Clone(v.Findings),
		RuntimeRequired: slices.Clone(v.RuntimeRequired), SameDefinition: v.SameDefinitionAs != ""}
}

// Check runs every check a write would run, without sending anything: the
// fields exist in this version, the values fit their types and options, no
// field is set by the firewall, and writes are allowed. For an entry list
// the values are checked for both add and set. Use it at plan time; the
// firewall's own validation (ErrValidation) still happens on write.
// Where writes are refused (read-only mode, a package older than the
// data) the values are still checked: the result joins their errors with
// the *ErrReadOnly, so a read-only tool can validate a configuration.
func (e *Entries) Check(v Values) error {
	b := e.b
	return errors.Join(e.checkValues(v), b.writable())
}

func (e *Entries) checkValues(v Values) error {
	b := e.b
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
	var valErr error
	if op, err := b.op("set"); err != nil {
		valErr = err
	} else {
		_, _, valErr = b.encode(v, op)
	}
	return errors.Join(valErr, b.writable())
}

func cloneFields(m map[string]*capability.Field) map[string]*capability.Field {
	out := make(map[string]*capability.Field, len(m))
	for k, f := range m {
		out[k] = f.Clone()
	}
	return out
}
