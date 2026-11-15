// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Entries is an entry list (entries keyed by UUID), for example
// "unbound/settings#hosts.host".
type Entries struct{ b *bound }

// Settings is a settings model (one object), for example "unbound/settings".
type Settings struct{ b *bound }

// Entries returns the entry list with this identifier, or ErrNotAvailable.
func (c *Client) Entries(id string) (*Entries, error) {
	b, err := c.bind(id, "entries")
	if err != nil {
		return nil, err
	}
	return &Entries{b}, nil
}

// Settings returns the settings resource with this identifier, or
// ErrNotAvailable.
func (c *Client) Settings(id string) (*Settings, error) {
	b, err := c.bind(id, "settings")
	if err != nil {
		return nil, err
	}
	return &Settings{b}, nil
}

// Fields returns the fields of the resource in the firewall's version.
func (e *Entries) Fields() map[string]*capability.Field { return e.b.res.FieldsFor(e.b.frag) }

// Fields returns the fields of the resource in the firewall's version.
func (s *Settings) Fields() map[string]*capability.Field { return s.b.res.FieldsFor(s.b.frag) }

// Add creates an entry and returns its UUID. If the read-back differs, the
// entry exists and the UUID is returned together with ErrNotApplied.
func (e *Entries) Add(ctx context.Context, v Values) (string, error) {
	b := e.b
	op, err := b.op("add")
	if err != nil {
		return "", err
	}
	body, sent, err := b.encode(v, true)
	if err != nil {
		return "", err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.t.Post(ctx, op.Path, map[string]any{b.wrapper(op): body}, &resp, 0); err != nil {
		return "", err
	}
	if err := b.result(resp, "saved"); err != nil {
		return "", err
	}
	id, _ := resp["uuid"].(string)
	if id == "" {
		return "", fmt.Errorf("opnsense: %s: add answered without uuid", b.id)
	}
	if err := b.c.afterMutation(ctx, b.api.Apply); err != nil {
		return id, err
	}
	return id, b.readBack(ctx, id, sent)
}

// Get reads one entry; ErrNotFound if it does not exist.
func (e *Entries) Get(ctx context.Context, id string) (Values, error) {
	obj, err := e.b.getObject(ctx, id)
	if err != nil {
		return nil, err
	}
	return e.b.decode(obj)
}

// Set changes the given fields of an entry; other fields keep their values.
func (e *Entries) Set(ctx context.Context, id string, v Values) error {
	b := e.b
	op, err := b.op("set")
	if err != nil {
		return err
	}
	body, sent, err := b.encode(v, false)
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	// the entry must exist: for an unknown UUID OPNsense creates a new entry
	// under that UUID (seen on 26.7.9), which would silently undo a delete
	if _, err := b.getObject(ctx, id); err != nil {
		return err
	}
	var resp map[string]any
	if err := b.c.t.Post(ctx, b.path(op, id), map[string]any{b.wrapper(op): body}, &resp, 0); err != nil {
		return err
	}
	if err := b.result(resp, "saved"); err != nil {
		return err
	}
	if err := b.c.afterMutation(ctx, b.api.Apply); err != nil {
		return err
	}
	return b.readBack(ctx, id, sent)
}

// Delete removes an entry; ErrNotFound if it did not exist.
func (e *Entries) Delete(ctx context.Context, id string) error {
	b := e.b
	op, err := b.op("del")
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.t.Post(ctx, b.path(op, id), nil, &resp, 0); err != nil {
		return err
	}
	if r, _ := resp["result"].(string); r == "not found" {
		return ErrNotFound
	}
	if err := b.result(resp, "deleted"); err != nil {
		return err
	}
	return b.c.afterMutation(ctx, b.api.Apply)
}

// List returns the UUIDs of all entries.
func (e *Entries) List(ctx context.Context) ([]string, error) {
	b := e.b
	op, err := b.op("search")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Rows []struct {
			UUID string `json:"uuid"`
		} `json:"rows"`
	}
	if hasMethod(op, "POST") {
		err = b.c.t.Post(ctx, op.Path, map[string]any{"current": 1, "rowCount": -1}, &resp, 0)
	} else {
		err = b.c.t.Get(ctx, op.Path+"?current=1&rowCount=-1", &resp)
	}
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		if r.UUID != "" {
			ids = append(ids, r.UUID)
		}
	}
	return ids, nil
}

// Get reads the settings.
func (s *Settings) Get(ctx context.Context) (Values, error) {
	obj, err := s.b.getObject(ctx, "")
	if err != nil {
		return nil, err
	}
	return s.b.decode(obj)
}

// Set changes the given fields; other fields keep their values.
func (s *Settings) Set(ctx context.Context, v Values) error {
	b := s.b
	op, err := b.op("set")
	if err != nil {
		return err
	}
	body, sent, err := b.encode(v, false)
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.t.Post(ctx, op.Path, map[string]any{b.wrapper(op): body}, &resp, 0); err != nil {
		return err
	}
	if err := b.result(resp, "saved"); err != nil {
		return err
	}
	if err := b.c.afterMutation(ctx, b.api.Apply); err != nil {
		return err
	}
	return b.readBack(ctx, "", sent)
}

// ---------------------------------------------------------------- helpers

func (b *bound) op(name string) (*capability.Operation, error) {
	if b.api == nil || b.api.Operations[name] == nil {
		return nil, fmt.Errorf("opnsense: %s has no %q operation in %s %s", b.id, name, b.pkg, b.version)
	}
	return b.api.Operations[name], nil
}

func (b *bound) wrapper(op *capability.Operation) string {
	if op.Wrapper != "" {
		return op.Wrapper
	}
	return b.api.Wrapper
}

func (b *bound) path(op *capability.Operation, args ...string) string {
	p := op.Path
	for _, a := range args {
		p += "/" + url.PathEscape(a)
	}
	return p
}

func hasMethod(op *capability.Operation, m string) bool {
	for _, x := range op.Methods {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return false
}

// encode checks and encodes values: nested request body and the sent wire
// value per field (for the read-back).
func (b *bound) encode(v Values, add bool) (map[string]any, map[string]string, error) {
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	body := map[string]any{}
	sent := map[string]string{}
	problems := map[string]string{}
	for _, name := range names {
		f := b.res.FieldFor(name, b.frag)
		if f == nil {
			return nil, nil, &ErrFieldNotAvailable{Resource: b.id, Field: name, Package: b.pkg, Have: b.version,
				AvailableIn: b.c.versions(b.pkg, b.fieldFragments(name))}
		}
		s, err := f.Encode(v[name])
		if err != nil {
			problems[name] = err.Error()
			continue
		}
		if err := setPath(body, name, s); err != nil {
			problems[name] = err.Error()
			continue
		}
		sent[name] = s
	}
	if add {
		var runtime []string
		if b.verified != nil {
			runtime = b.verified.RuntimeRequired
		}
		for name, f := range b.res.FieldsFor(b.frag) {
			if _, given := v[name]; given || f.ServerSet() {
				continue
			}
			switch {
			case f.Required && f.Default == nil:
				problems[name] = "required"
			case contains(runtime, name):
				problems[name] = "required by the firewall (found by the contract test)"
			}
		}
	}
	if len(problems) > 0 {
		return nil, nil, &ErrInvalid{Resource: b.id, Problems: problems}
	}
	return body, sent, nil
}

// fieldFragments: fragments in which the resource has this field.
func (b *bound) fieldFragments(name string) []string {
	var out []string
	for _, h := range b.res.In {
		if b.res.FieldFor(name, h) != nil {
			out = append(out, h)
		}
	}
	return out
}

func setPath(m map[string]any, path, value string) error {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p]
		if !ok {
			child := map[string]any{}
			m[p] = child
			m = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is a field, not a container", p)
		}
		m = child
	}
	m[parts[len(parts)-1]] = value
	return nil
}

func lookup(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// getObject reads the object (entry with id, or the settings with id "")
// and returns it without wrapper; ErrNotFound for a missing entry.
func (b *bound) getObject(ctx context.Context, id string) (map[string]any, error) {
	op, err := b.op("get")
	if err != nil {
		return nil, err
	}
	p := op.Path
	if id != "" {
		p = b.path(op, id)
	}
	var raw any
	if err := b.c.t.Get(ctx, p, &raw); err != nil {
		return nil, err
	}
	root, ok := raw.(map[string]any)
	if !ok || len(root) == 0 {
		if id != "" {
			return nil, ErrNotFound // OPNsense answers [] for an unknown UUID
		}
		return nil, fmt.Errorf("opnsense: %s: empty answer", b.id)
	}
	if op.Outer != "" {
		if root, ok = root[op.Outer].(map[string]any); !ok {
			return nil, fmt.Errorf("opnsense: %s: key %q missing in the answer", b.id, op.Outer)
		}
	}
	obj, ok := root[b.wrapper(op)].(map[string]any)
	if !ok {
		if id != "" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("opnsense: %s: key %q missing in the answer", b.id, b.wrapper(op))
	}
	return obj, nil
}

func (b *bound) decode(obj map[string]any) (Values, error) {
	out := Values{}
	for name, f := range b.res.FieldsFor(b.frag) {
		raw, ok := lookup(obj, name)
		if !ok {
			continue
		}
		s, err := f.Wire(raw)
		if err != nil {
			return nil, fmt.Errorf("opnsense: %s field %s: %w", b.id, name, err)
		}
		v, err := f.Decode(s)
		if err != nil {
			return nil, fmt.Errorf("opnsense: %s field %s: %w", b.id, name, err)
		}
		out[name] = v
	}
	return out, nil
}

// readBack compares what was sent with what the firewall now returns.
// Write-only and volatile fields are skipped.
func (b *bound) readBack(ctx context.Context, id string, sent map[string]string) error {
	obj, err := b.getObject(ctx, id)
	if err != nil {
		return fmt.Errorf("opnsense: %s: reading back after the write: %w", b.id, err)
	}
	var diffs []FieldDiff
	names := make([]string, 0, len(sent))
	for k := range sent {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		f := b.res.FieldFor(name, b.frag)
		if f.WriteOnly() || f.Volatile {
			continue
		}
		raw, ok := lookup(obj, name)
		got := ""
		if ok {
			if got, err = f.Wire(raw); err != nil {
				return fmt.Errorf("opnsense: %s field %s: %w", b.id, name, err)
			}
		}
		if !ok || !f.SameWire(sent[name], got) {
			if !ok {
				got = "(missing)"
			}
			diffs = append(diffs, FieldDiff{Field: name, Sent: sent[name], Got: got})
		}
	}
	if len(diffs) > 0 {
		return &ErrNotApplied{Resource: b.id, ID: id, Diffs: diffs}
	}
	return nil
}

// result checks the "result" of a mutation.
func (b *bound) result(resp map[string]any, want string) error {
	r, _ := resp["result"].(string)
	if r == want {
		return nil
	}
	if r == "failed" {
		e := &ErrValidation{Resource: b.id, Fields: map[string]string{}}
		vals, _ := resp["validations"].(map[string]any)
		for k, msg := range vals {
			// keys are "<wrapper>.<field path>"
			if _, rest, ok := strings.Cut(k, "."); ok {
				k = rest
			}
			e.Fields[k] = fmt.Sprint(msg)
		}
		if len(e.Fields) == 0 {
			e.Body = fmt.Sprint(resp)
		}
		return e
	}
	return fmt.Errorf("opnsense: %s: unexpected answer %v", b.id, resp)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
