// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
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

// Apply calls the apply endpoint of this resource, whether or not this
// Client saved a change: a change saved by an earlier process (whose apply
// failed or never ran) must still be activatable. A resource without an
// apply endpoint is active when saved; then nothing is sent.
func (e *Entries) Apply(ctx context.Context) error {
	return e.b.c.applyEndpoint(ctx, e.b.api.Apply, true)
}

// Apply calls the apply endpoint of this resource unconditionally (see
// Entries.Apply).
func (s *Settings) Apply(ctx context.Context) error {
	return s.b.c.applyEndpoint(ctx, s.b.api.Apply, true)
}

// Entry IDs are usually UUIDs, but not always: interface assignments use
// names ("wan", "opt1"), aliases their name ("bogons"), tunables a hash.
// Accepted are letters, digits, '_', '-' and '.', not starting with a dot,
// at most 128 characters: safe in a URL path without escaping, and no "."
// or ".." segment can be formed.
var idRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

// ErrBadID: an entry ID contains characters no OPNsense ID has; it never
// reaches the firewall.
var ErrBadID = errors.New("opnsense: invalid entry ID")

func checkID(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrBadID, id)
	}
	return nil
}

// Add creates an entry and returns its UUID. If the read-back differs, the
// entry exists and the UUID is returned together with ErrNotApplied.
func (e *Entries) Add(ctx context.Context, v Values) (string, error) {
	b := e.b
	if err := b.writable(); err != nil {
		return "", err
	}
	op, err := b.op("add")
	if err != nil {
		return "", err
	}
	body, sent, err := b.encode(v, op)
	if err != nil {
		return "", err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.post(ctx, op.Path, map[string]any{b.wrapper(op): body}, &resp, b.api.Apply); err != nil {
		return "", err
	}
	if err := b.result(resp, "saved", "add", ""); err != nil {
		return "", err
	}
	b.c.markPending(b.api.Apply)
	id, _ := resp["uuid"].(string)
	if checkID(id) != nil {
		// "saved" without a usable id: the entry was probably created
		return "", &ErrUnexpectedAnswer{Resource: b.id, Operation: "add", Answer: fmt.Sprint(resp)}
	}
	return id, b.c.finish(ctx, b.api.Apply, b.readBack(ctx, id, sent, op))
}

// Get reads one entry; ErrNotFound if it does not exist. With an
// *ErrDecode error the decodable fields are returned as well.
func (e *Entries) Get(ctx context.Context, id string) (Values, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	obj, err := e.b.getObject(ctx, id)
	if err != nil {
		return nil, err
	}
	if e.b.incomplete(obj) || e.b.isTemplate(ctx, obj) {
		// some plugins answer an unknown UUID with a blank template instead
		// of [] (os-nginx error pages on 26.7.9), partial or complete: the
		// list decides
		if err := e.b.exists(ctx, id); err != nil {
			return nil, err
		}
	}
	return e.b.decode(obj)
}

// GetRaw reads one entry as the firewall returns it (without the wrapper
// key), for debugging and for values the typed model does not cover.
func (e *Entries) GetRaw(ctx context.Context, id string) (map[string]any, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	return e.b.getObject(ctx, id)
}

// Set changes the given fields of an entry; other fields keep their values.
func (e *Entries) Set(ctx context.Context, id string, v Values) error {
	b := e.b
	if err := b.writable(); err != nil {
		return err
	}
	if err := checkID(id); err != nil {
		return err
	}
	op, err := b.op("set")
	if err != nil {
		return err
	}
	body, sent, err := b.encode(v, op)
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	// The entry must exist: for an unknown UUID OPNsense creates a new entry
	// under that UUID (seen on 26.7.9), which would silently undo a delete.
	// The model lock keeps this client's own deletes out of the gap; a
	// delete by someone else in between cannot be excluded.
	if err := b.exists(ctx, id); err != nil {
		return err
	}
	var resp map[string]any
	if err := b.c.post(ctx, b.path(op, id), map[string]any{b.wrapper(op): body}, &resp, b.api.Apply); err != nil {
		return err
	}
	if err := b.result(resp, "saved", "set", id); err != nil {
		return err
	}
	b.c.markPending(b.api.Apply)
	return b.c.finish(ctx, b.api.Apply, b.readBack(ctx, id, sent, op))
}

// Delete removes an entry and confirms it is gone; ErrNotFound if it did
// not exist.
func (e *Entries) Delete(ctx context.Context, id string) error {
	b := e.b
	if err := b.writable(); err != nil {
		return err
	}
	if err := checkID(id); err != nil {
		return err
	}
	op, err := b.op("del")
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.post(ctx, b.path(op, id), nil, &resp, b.api.Apply); err != nil {
		return err
	}
	if r, _ := resp["result"].(string); r == "not found" {
		return ErrNotFound
	}
	if _, answered := resp["result"]; answered || !op.HasGap(capability.GapResultNotReturned) {
		if err := b.result(resp, "deleted", "del", id); err != nil {
			return err
		}
	} // else: the endpoint answers nothing; the check below decides
	b.c.markPending(b.api.Apply)
	var confirm error
	if err := b.exists(ctx, id); !errors.Is(err, ErrNotFound) {
		if err == nil {
			confirm = &ErrStillExists{Resource: b.id, ID: id}
		} else {
			confirm = fmt.Errorf("opnsense: %s %s: confirming the delete: %w", b.id, id, err)
		}
	}
	return b.c.finish(ctx, b.api.Apply, confirm)
}

// Toggle enables or disables an entry through the resource's toggle
// operation and confirms the new state by reading the entry again
// (ErrNotApplied if it did not change). Without a target-state parameter
// the endpoint flips the state, so the current one is read first.
func (e *Entries) Toggle(ctx context.Context, id string, enabled bool) error {
	b := e.b
	if err := b.writable(); err != nil {
		return err
	}
	if err := checkID(id); err != nil {
		return err
	}
	op, err := b.op("toggle")
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	// an unknown UUID must not be trusted either: check and read first
	if err := b.exists(ctx, id); err != nil {
		return err
	}
	obj, err := b.getObject(ctx, id)
	if err != nil {
		return err
	}
	p := b.path(op, id)
	if len(op.Params) >= 2 {
		p = b.path(op, id, map[bool]string{true: "1", false: "0"}[enabled])
	} else {
		cur, ok := lookup(obj, "enabled")
		if !ok {
			return fmt.Errorf("opnsense: %s: toggle flips a state the entry does not show (no field \"enabled\")", b.id)
		}
		if s, _ := cur.(string); s == map[bool]string{true: "1", false: "0"}[enabled] {
			return nil // already in the wanted state
		}
	}
	var resp map[string]any
	if err := b.c.post(ctx, p, nil, &resp, b.api.Apply); err != nil {
		return err
	}
	b.c.markPending(b.api.Apply) // the toggle reached the firewall
	// the entry decides, not the answer
	wantWire := map[bool]string{true: "1", false: "0"}[enabled]
	var check error
	if _, has := lookup(obj, "enabled"); has {
		after, err := b.getObject(ctx, id)
		if err != nil {
			return b.c.finish(ctx, b.api.Apply, fmt.Errorf("opnsense: %s %s: reading back after the toggle: %w", b.id, id, err))
		}
		got, _ := lookup(after, "enabled")
		if s, _ := got.(string); s != wantWire {
			check = &ErrNotApplied{Resource: b.id, ID: id, Diffs: []FieldDiff{{Field: "enabled", Sent: wantWire, Got: fmt.Sprint(got)}}}
		}
	} else if r, _ := resp["result"].(string); r != map[bool]string{true: "Enabled", false: "Disabled"}[enabled] {
		// no "enabled" field to read: only the answer can tell
		check = &ErrUnexpectedAnswer{Resource: b.id, Operation: "toggle", ID: id, Answer: fmt.Sprint(resp)}
	}
	return b.c.finish(ctx, b.api.Apply, check)
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
		Total *int `json:"total"`
	}
	if hasMethod(op, "POST") {
		err = b.c.t.Search(ctx, op.Path, &resp)
	} else {
		err = b.c.t.Get(ctx, op.Path, url.Values{"current": {"1"}, "rowCount": {"-1"}}, &resp)
	}
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		if checkID(r.UUID) != nil {
			return nil, fmt.Errorf("opnsense: %s: search returned a row without a valid id", b.id)
		}
		ids = append(ids, r.UUID)
	}
	// fewer rows than the total: the answer was paged or cut, the list is
	// incomplete. More rows than the total is OPNsense's doing: the
	// firewall/d_nat search of 26.1 adds two anti-lockout rules
	// ("lockout_0", "lockout_1") that it does not count (ADR 0001).
	if resp.Total != nil && len(ids) < *resp.Total {
		return nil, &ErrIncompleteList{Resource: b.id, Got: len(ids), Total: *resp.Total}
	}
	return ids, nil
}

// Get reads the settings. With an *ErrDecode error the decodable fields
// are returned as well.
func (s *Settings) Get(ctx context.Context) (Values, error) {
	obj, err := s.b.getObject(ctx, "")
	if err != nil {
		return nil, err
	}
	return s.b.decode(obj)
}

// GetRaw reads the settings as the firewall returns them (without the
// wrapper key).
func (s *Settings) GetRaw(ctx context.Context) (map[string]any, error) {
	return s.b.getObject(ctx, "")
}

// Set changes the given fields; other fields keep their values.
func (s *Settings) Set(ctx context.Context, v Values) error {
	b := s.b
	if err := b.writable(); err != nil {
		return err
	}
	op, err := b.op("set")
	if err != nil {
		return err
	}
	body, sent, err := b.encode(v, op)
	if err != nil {
		return err
	}
	defer b.c.lock(b.api.Model)()
	var resp map[string]any
	if err := b.c.post(ctx, op.Path, map[string]any{b.wrapper(op): body}, &resp, b.api.Apply); err != nil {
		return err
	}
	if err := b.result(resp, "saved", "set", ""); err != nil {
		return err
	}
	b.c.markPending(b.api.Apply)
	return b.c.finish(ctx, b.api.Apply, b.readBack(ctx, "", sent, op))
}

// ---------------------------------------------------------------- helpers

func (b *bound) op(name string) (*capability.Operation, error) {
	if b.api.Operations[name] == nil {
		return nil, &ErrNoOperation{Resource: b.id, Operation: name, Package: b.pkg, Have: b.version}
	}
	return b.api.Operations[name], nil
}

func (b *bound) wrapper(op *capability.Operation) string {
	if op.Wrapper != "" {
		return op.Wrapper
	}
	return b.api.Wrapper
}

// path appends already validated segments (UUIDs, "0"/"1"); the transport
// checks the result again.
func (b *bound) path(op *capability.Operation, args ...string) string {
	return op.Path + "/" + strings.Join(args, "/")
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
// Required fields are not checked here: the model's "required" is not
// reliable for add (controllers fill some of them, e.g. the traffic shaper
// pipe number), and the firewall reports a missing value as ErrValidation.
func (b *bound) encode(v Values, op *capability.Operation) (map[string]any, map[string]string, error) {
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
		if f.ServerSet {
			problems[name] = "set by the firewall; it cannot be written"
			continue
		}
		if f.Volatile {
			problems[name] = "not stored by the firewall (volatile); it cannot be managed"
			continue
		}
		if how, ok := op.Overwrites(name); ok {
			problems[name] = how + "; a value sent would be overwritten"
			continue
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
	if _, ok := m[parts[len(parts)-1]].(map[string]any); ok {
		return fmt.Errorf("%s is a container, not a field", path)
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
	if err := b.c.t.Get(ctx, p, nil, &raw); err != nil {
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
	inner := root[b.wrapper(op)]
	if l, isList := inner.([]any); isList && len(l) == 0 && id == "" {
		// a model without fields arrives as an empty list (os-netbird status)
		return map[string]any{}, nil
	}
	obj, ok := inner.(map[string]any)
	if !ok {
		if id != "" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("opnsense: %s: key %q missing in the answer", b.id, b.wrapper(op))
	}
	return obj, nil
}

// exists reports ErrNotFound unless the entry is there. The search is
// authoritative: a get of an unknown UUID answers [] in most controllers
// but a blank template in some. Without a search operation, the get
// decides.
func (b *bound) exists(ctx context.Context, id string) error {
	if _, ok := b.api.Operations["search"]; ok {
		ids, err := (&Entries{b}).List(ctx)
		if err != nil {
			return fmt.Errorf("opnsense: %s: checking that %s exists: %w", b.id, id, err)
		}
		for _, x := range ids {
			if x == id {
				return nil
			}
		}
		return ErrNotFound
	}
	_, err := b.getObject(ctx, id)
	return err
}

// incomplete: the object lacks fields every entry of this resource has.
func (b *bound) incomplete(obj map[string]any) bool {
	for name, f := range b.res.FieldsFor(b.frag) {
		if f.WriteOnly || f.Volatile {
			continue
		}
		if _, ok := lookup(obj, name); !ok {
			return true
		}
	}
	return false
}

// decode returns every field it can decode; fields with an unexpected
// shape are reported in *ErrDecode together with the rest. Write-only
// fields are left out (the firewall never returns their value).
func (b *bound) decode(obj map[string]any) (Values, error) {
	out := Values{}
	bad := map[string]string{}
	for name, f := range b.res.FieldsFor(b.frag) {
		if f.WriteOnly {
			continue
		}
		raw, ok := lookup(obj, name)
		if !ok {
			continue
		}
		s, err := f.Wire(raw)
		if err == nil {
			var v any
			if v, err = f.Decode(s); err == nil {
				out[name] = v
				continue
			}
		}
		bad[name] = err.Error()
	}
	if len(bad) > 0 {
		return out, &ErrDecode{Resource: b.id, Fields: bad}
	}
	return out, nil
}

// readBack compares what was sent with what the firewall now returns.
// Write-only fields (never returned) are skipped; volatile fields are never
// sent (encode refuses them); transformed fields (stored in another form by
// this endpoint) must at least not come back empty.
func (b *bound) readBack(ctx context.Context, id string, sent map[string]string, op *capability.Operation) error {
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
		if f.WriteOnly || f.Volatile {
			continue
		}
		if op != nil && op.Transforms(name) {
			// stored in another form: the value cannot be compared, but a
			// value sent must not come back empty
			if raw, ok := lookup(obj, name); sent[name] != "" && (!ok || raw == nil || raw == "") {
				diffs = append(diffs, FieldDiff{Field: name, Sent: sent[name], Got: "", Cause: CauseTransformed})
			}
			continue
		}
		raw, ok := lookup(obj, name)
		got := "(missing)"
		if ok {
			if got, err = f.Wire(raw); err != nil {
				got = "(" + err.Error() + ")"
				ok = false
			}
		}
		if !ok || !f.SameWire(sent[name], got) {
			d := FieldDiff{Field: name, Sent: sent[name], Got: got}
			switch {
			case f.CustomWrite():
				d.Cause = CauseCustomWrite
			case b.api.CustomSave():
				d.Cause = CauseCustomSave
			}
			diffs = append(diffs, d)
		}
	}
	if len(diffs) > 0 {
		e := &ErrNotApplied{Resource: b.id, ID: id, Diffs: diffs}
		var hints []string
		if op.HasGap(capability.GapOverlayUnknown) {
			hints = append(hints, op.Path+" overwrites fields it does not declare (gap overlay-unknown)")
		}
		for _, d := range diffs {
			switch d.Cause {
			case CauseCustomWrite:
				hints = append(hints, d.Field+": its field type converts values on write (gap custom-write)")
			case CauseCustomSave:
				hints = append(hints, "the firewall stores "+b.id+" through its own code, which may change or drop values that do not apply to the rest of the entry (gap custom-save)")
			}
		}
		e.Hint = strings.Join(uniq(hints), "; ")
		return e
	}
	return nil
}

// result checks the "result" of a mutation (operation op on entry id).
// "failed" is a validation error and changed nothing; any other answer
// may have changed something, so the apply endpoint is marked pending.
func (b *bound) result(resp map[string]any, want, op, id string) error {
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
			e.Fields[k] = transport.Trunc([]byte(fmt.Sprint(msg)))
		}
		if len(e.Fields) == 0 {
			e.Body = transport.Trunc([]byte(fmt.Sprint(resp)))
		}
		return e
	}
	b.c.markPending(b.api.Apply)
	return &ErrUnexpectedAnswer{Resource: b.id, Operation: op, ID: id, Answer: fmt.Sprint(resp)}
}

// uniq keeps the first occurrence of each string, in order.
func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// isTemplate: the object equals the blank template of a new entry (what
// get answers without a UUID). Fetched once per entry list and client; an
// endpoint that needs a UUID has no template, and then this is false.
func (b *bound) isTemplate(ctx context.Context, obj map[string]any) bool {
	op, err := b.op("get")
	if err != nil || len(op.Params) == 0 || !strings.HasSuffix(op.Params[0], "?") {
		return false
	}
	b.c.mu.Lock()
	tmpl, ok := b.c.templates[b.id]
	b.c.mu.Unlock()
	if !ok {
		t, err := b.getObject(ctx, "")
		if err != nil {
			return false
		}
		tmpl = t
		b.c.mu.Lock()
		b.c.templates[b.id] = tmpl
		b.c.mu.Unlock()
	}
	return reflect.DeepEqual(obj, tmpl)
}
