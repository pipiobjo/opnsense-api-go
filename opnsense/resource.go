// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

// Fields returns the raw field descriptions of the resource in the
// firewall's version, as copies. Prefer Info().Fields: it does not tie a
// consumer to the data format.
func (e *Entries) Fields() map[string]*capability.Field {
	return cloneFields(e.b.res.FieldsFor(e.b.frag))
}

// Fields returns copies of the raw field descriptions (see Entries.Fields).
func (s *Settings) Fields() map[string]*capability.Field {
	return cloneFields(s.b.res.FieldsFor(s.b.frag))
}

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
	unlock, err := b.c.lock(ctx, b.api.Model)
	if err != nil {
		return "", err
	}
	defer unlock()
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
		return "", &ErrUnexpectedAnswer{Resource: b.id, Operation: "add", Answer: transport.Trunc([]byte(fmt.Sprint(resp)))}
	}
	rb := b.readBack(ctx, id, sent, op)
	unlock() // an apply can take minutes; other changes to the model need not wait
	return id, b.c.finish(ctx, b.api.Apply, rb)
}

// Get reads one entry; ErrNotFound if it does not exist. With an
// *ErrDecode error the decodable fields are returned as well.
func (e *Entries) Get(ctx context.Context, id string) (Values, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	obj, err := e.b.exists(ctx, id)
	if err != nil {
		return nil, err
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
	unlock, err := b.c.lock(ctx, b.api.Model)
	if err != nil {
		return err
	}
	defer unlock()
	// The entry must exist: for an unknown UUID OPNsense creates a new entry
	// under that UUID (seen on 26.7.9), which would silently undo a delete.
	// The model lock keeps this client's own deletes out of the gap; a
	// delete by someone else in between cannot be excluded.
	if _, err := b.exists(ctx, id); err != nil {
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
	rb := b.readBack(ctx, id, sent, op)
	unlock()
	return b.c.finish(ctx, b.api.Apply, rb)
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
	unlock, err := b.c.lock(ctx, b.api.Model)
	if err != nil {
		return err
	}
	defer unlock()
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
	if _, err := b.exists(ctx, id); !errors.Is(err, ErrNotFound) {
		if err == nil {
			confirm = &ErrStillExists{Resource: b.id, ID: id}
		} else {
			confirm = fmt.Errorf("opnsense: %s %s: confirming the delete: %w", b.id, id, err)
		}
	}
	unlock()
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
	unlock, err := b.c.lock(ctx, b.api.Model)
	if err != nil {
		return err
	}
	defer unlock()
	// an unknown UUID must not be trusted either: check and read first
	obj, err := b.exists(ctx, id)
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
			unlock()
			return b.c.finish(ctx, b.api.Apply, fmt.Errorf("opnsense: %s %s: reading back after the toggle: %w", b.id, id, err))
		}
		got, _ := lookup(after, "enabled")
		if s, _ := got.(string); s != wantWire {
			check = &ErrNotApplied{Resource: b.id, ID: id, Diffs: []FieldDiff{{Field: "enabled", Sent: wantWire, Got: fmt.Sprint(got)}}}
		}
	} else if r, _ := resp["result"].(string); r != map[bool]string{true: "Enabled", false: "Disabled"}[enabled] {
		// no "enabled" field to read: only the answer can tell
		check = &ErrUnexpectedAnswer{Resource: b.id, Operation: "toggle", ID: id, Answer: transport.Trunc([]byte(fmt.Sprint(resp)))}
	}
	unlock()
	return b.c.finish(ctx, b.api.Apply, check)
}

// List returns the IDs of all entries, in one request.
func (e *Entries) List(ctx context.Context) ([]string, error) {
	rows, err := e.b.search(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.id
	}
	return ids, nil
}

// Row is one entry as the list's search returns it.
type Row struct {
	ID string
	// Values holds the entry's fields that the search returned, decoded
	// as Get decodes them. OPNsense's standard search returns every field
	// of the entry; a controller with its own search may return fewer, so
	// a field missing here is not proof that the entry lacks it.
	// Never included: write-only fields, and fields whose stored form,
	// which the search shows, differs from what Get shows (the data marks
	// them: stored transformed, or rendered by the field type's own read
	// code into a string, such as an audit trail). Read those with Get.
	Values Values
}

// Rows returns every entry with its fields, in one request (Get per entry
// would be one request each). A field with an unexpected shape is left out
// of its row and named in an *ErrDecode, keyed "<id> <field>", which is
// returned together with all rows.
func (e *Entries) Rows(ctx context.Context) ([]Row, error) {
	rows, err := e.b.search(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Row, len(rows))
	bad := map[string]string{}
	for i, r := range rows {
		out[i] = Row{ID: r.id, Values: e.b.decodeRow(r, bad)}
	}
	return out, decodeErr(e.b.id, bad)
}

// Find returns the entries whose fields equal every value in match, in
// one search: for example the host override with a given hostname and
// domain, to find an entry a caller created before without knowing its ID,
// or to avoid creating a duplicate (OPNsense does not refuse those).
// Values are compared as the firewall stores them (encoded as Add would
// send them; lists as sets), so match takes the same values as Add. A
// field the data does not have for this version is ErrFieldNotAvailable;
// a value that could not be sent, a write-only field (never returned) or a
// transformed one (stored in another form) is ErrInvalid. Where the search
// does not show a field as Get does, that entry is read with Get. Rows and
// *ErrDecode as in Rows.
func (e *Entries) Find(ctx context.Context, match Values) ([]Row, error) {
	b := e.b
	want := make(map[string]string, len(match))
	problems := map[string]string{}
	for name, v := range match {
		f := b.res.FieldFor(name, b.frag)
		if f == nil {
			return nil, &ErrFieldNotAvailable{Resource: b.id, Field: name, Package: b.pkg, Have: b.version,
				AvailableIn: b.c.versions(b.pkg, b.fieldFragments(name))}
		}
		if f.WriteOnly {
			problems[name] = "write-only: the firewall never returns its value"
			continue
		}
		if b.transformed(name) {
			problems[name] = "stored in another form than sent (transformed); it cannot be compared"
			continue
		}
		s, err := f.Encode(v)
		if err != nil {
			problems[name] = err.Error()
			continue
		}
		want[name] = s
	}
	if len(problems) > 0 {
		return nil, &ErrInvalid{Resource: b.id, Problems: problems}
	}
	rows, err := b.search(ctx)
	if err != nil {
		return nil, err
	}
	var out []Row
	bad := map[string]string{}
	for _, r := range rows {
		ok, err := b.matches(ctx, r, want)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, Row{ID: r.id, Values: b.decodeRow(r, bad)})
		}
	}
	return out, decodeErr(b.id, bad)
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
	unlock, err := b.c.lock(ctx, b.api.Model)
	if err != nil {
		return err
	}
	defer unlock()
	var resp map[string]any
	if err := b.c.post(ctx, op.Path, map[string]any{b.wrapper(op): body}, &resp, b.api.Apply); err != nil {
		return err
	}
	if err := b.result(resp, "saved", "set", ""); err != nil {
		return err
	}
	b.c.markPending(b.api.Apply)
	rb := b.readBack(ctx, "", sent, op)
	unlock()
	return b.c.finish(ctx, b.api.Apply, rb)
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

// exists returns the entry as get answers it, or ErrNotFound. For an
// unknown ID most controllers' get answers [], but some answer a blank
// template (os-nginx error pages on 26.7.9, partial or complete), and set
// creates a new entry under an unknown ID. Where get cannot tell
// (getDecides), the search decides. One GET in the usual case; a full
// search only for controllers that answer unknown IDs with a template.
// An answer get cannot read (some controllers answer an unknown ID
// without their outer key, os-squid's PAC entries on 26.7.9) is decided by
// the search as well: not listed is ErrNotFound, listed returns the error.
func (b *bound) exists(ctx context.Context, id string) (map[string]any, error) {
	obj, err := b.getObject(ctx, id)
	if (err == nil || errors.Is(err, ErrNotFound)) && b.getDecides(ctx) {
		return obj, err
	}
	if _, ok := b.api.Operations["search"]; !ok {
		return obj, err
	}
	rows, serr := b.search(ctx)
	if serr != nil {
		return nil, fmt.Errorf("opnsense: %s: checking that %s exists: %w", b.id, id, serr)
	}
	for _, r := range rows {
		if r.id == id {
			return obj, err
		}
	}
	return nil, ErrNotFound
}

// probeID is an ID no entry has: the nil UUID.
const probeID = "00000000-0000-0000-0000-000000000000"

// getDecides: get answers an ID that does not exist with [] (ErrNotFound),
// so an object in its answer is an entry. Measured once per entry list and
// client by reading probeID; a template in the answer, or an error, leaves
// the decision to the search. Without a search operation get decides.
func (b *bound) getDecides(ctx context.Context) bool {
	if _, ok := b.api.Operations["search"]; !ok {
		return true
	}
	b.c.mu.Lock()
	v, known := b.c.getDecides[b.id]
	b.c.mu.Unlock()
	if known {
		return v
	}
	_, err := b.getObject(ctx, probeID)
	switch {
	case errors.Is(err, ErrNotFound):
		v = true
	case err != nil:
		return false // says nothing about the controller; ask again next time
	}
	b.c.mu.Lock()
	b.c.getDecides[b.id] = v
	b.c.mu.Unlock()
	return v
}

// searchRow is one row of a search answer: the entry's ID and its fields
// as the search returns them.
type searchRow struct {
	id  string
	raw map[string]any
}

// search returns all rows of the entry list in one request.
func (b *bound) search(ctx context.Context) ([]searchRow, error) {
	op, err := b.op("search")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Rows  []map[string]any `json:"rows"`
		Total *int             `json:"total"`
	}
	if hasMethod(op, "POST") {
		err = b.c.t.Search(ctx, op.Path, &resp)
	} else {
		err = b.c.t.Get(ctx, op.Path, url.Values{"current": {"1"}, "rowCount": {"-1"}}, &resp)
	}
	if err != nil {
		return nil, err
	}
	rows := make([]searchRow, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		id, _ := r["uuid"].(string)
		if checkID(id) != nil {
			return nil, fmt.Errorf("opnsense: %s: search returned a row without a valid id", b.id)
		}
		rows = append(rows, searchRow{id, r})
	}
	// fewer rows than the total: the answer was paged or cut, the list is
	// incomplete. More rows than the total is OPNsense's doing: the
	// firewall/d_nat search of 26.1 adds two anti-lockout rules
	// ("lockout_0", "lockout_1") that it does not count (ADR 0001).
	if resp.Total != nil && len(rows) < *resp.Total {
		return nil, &ErrIncompleteList{Resource: b.id, Got: len(rows), Total: *resp.Total}
	}
	return rows, nil
}

// field returns a field of a search row. OPNsense's search flattens an
// entry to dotted keys ("general.enabled"); a search of its own may nest.
// Keys starting with "%" are display texts and never match a field name.
func (r searchRow) field(name string) (any, bool) {
	if v, ok := r.raw[name]; ok {
		return v, true
	}
	return lookup(r.raw, name)
}

// transformed: the add or set operation stores the field in another form
// than sent (base64, for example).
func (b *bound) transformed(name string) bool {
	for _, op := range []string{"add", "set"} {
		if o := b.api.Operations[op]; o != nil && o.Transforms(name) {
			return true
		}
	}
	return false
}

// searchShows: a search row shows the field as get does. The search
// returns the stored value; get differs for a transformed field (the
// controller converts it back, as os-nginx error pages on 26.7.9) and for
// a field type with its own read code that renders a string
// (custom-read-shape: JsonAuditField shows "" on get but its JSON in the
// search). Option and relation fields (read shape "select") render the
// same value as a map, which decoding turns back into the stored value.
func (b *bound) searchShows(name string) bool {
	f := b.res.FieldFor(name, b.frag)
	if f == nil || b.transformed(name) {
		return false
	}
	return !f.CustomReadShape() || f.ReadShape == "select"
}

// decodeRow decodes the fields of a search row that it shows as get does;
// problems go to bad, keyed "<id> <field>".
func (b *bound) decodeRow(r searchRow, bad map[string]string) Values {
	out, problems := b.decodeWith(func(name string) (any, bool) {
		if !b.searchShows(name) {
			return nil, false
		}
		return r.field(name)
	})
	for f, p := range problems {
		bad[r.id+" "+f] = p
	}
	return out
}

// matches: every wanted wire value equals the entry's. A field the search
// row lacks is read from the entry itself.
func (b *bound) matches(ctx context.Context, r searchRow, want map[string]string) (bool, error) {
	var obj map[string]any
	for name, s := range want {
		raw, ok := r.field(name)
		if !ok || !b.searchShows(name) {
			if obj == nil {
				var err error
				if obj, err = b.getObject(ctx, r.id); err != nil {
					return false, fmt.Errorf("opnsense: %s %s: reading a field the search does not show: %w", b.id, r.id, err)
				}
			}
			if raw, ok = lookup(obj, name); !ok {
				return false, nil
			}
		}
		f := b.res.FieldFor(name, b.frag)
		got, err := f.Wire(raw)
		if err != nil {
			return false, &ErrDecode{Resource: b.id, Fields: map[string]string{r.id + " " + name: err.Error()}}
		}
		if !f.SameWire(s, got) {
			return false, nil
		}
	}
	return true, nil
}

// decodeErr is nil without problems, else an *ErrDecode.
func decodeErr(resource string, bad map[string]string) error {
	if len(bad) == 0 {
		return nil
	}
	return &ErrDecode{Resource: resource, Fields: bad}
}

// decode returns every field it can decode; fields with an unexpected
// shape are reported in *ErrDecode together with the rest. Write-only
// fields are left out (the firewall never returns their value).
func (b *bound) decode(obj map[string]any) (Values, error) {
	out, bad := b.decodeWith(func(name string) (any, bool) { return lookup(obj, name) })
	return out, decodeErr(b.id, bad)
}

// decodeWith decodes every field of the resource that get returns; the
// problems are keyed by field.
func (b *bound) decodeWith(get func(string) (any, bool)) (Values, map[string]string) {
	out := Values{}
	bad := map[string]string{}
	for name, f := range b.res.FieldsFor(b.frag) {
		if f.WriteOnly {
			continue
		}
		raw, ok := get(name)
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
	return out, bad
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
	return &ErrUnexpectedAnswer{Resource: b.id, Operation: op, ID: id, Answer: transport.Trunc([]byte(fmt.Sprint(resp)))}
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
