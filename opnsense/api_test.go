// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Claim: Fields lists exactly the fields of the resolved version, the
// same set the client accepts for writing; GetRaw returns the firewall's
// own answer without the wrapper key.
func TestFieldsAndGetRaw(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	fields := n.Fields()
	for _, name := range []string{"enabled", "address", "description", "pollinterval", "priority"} {
		if fields[name] == nil {
			t.Errorf("Fields lacks %s: %v", name, fields)
		}
	}
	for name := range fields {
		if _, _, err := n.b.encode(Values{name: nil}, mustOp(t, n.b, "add")); err != nil {
			var fna *ErrFieldNotAvailable
			if errors.As(err, &fna) {
				t.Errorf("Fields lists %s, but writing it is refused as not available", name)
			}
		}
	}
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := n.GetRaw(ctx, id)
	if err != nil || raw["address"] != "192.0.2.10" || raw["neighbor"] != nil {
		t.Errorf("GetRaw: %v %v", raw, err)
	}
	if _, err := n.GetRaw(ctx, "../x"); !errors.Is(err, ErrBadID) {
		t.Errorf("GetRaw with a bad ID: %v", err)
	}
	s, _ := c.Settings("quagga/ospfsettings")
	if s.Fields()["routerid"] == nil {
		t.Error("settings Fields lacks routerid")
	}
	sraw, err := s.GetRaw(ctx)
	if err != nil || sraw["routerid"] == nil || sraw["ospf"] != nil {
		t.Errorf("settings GetRaw: %v %v", sraw, err)
	}
}

func mustOp(t *testing.T, b *bound, name string) *capability.Operation {
	t.Helper()
	op, err := b.op(name)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// Claim (README): Entries.Apply and Settings.Apply activate only the apply
// endpoint of their own resource and clear it from the pending list.
func TestResourceApply(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	s, _ := c.Settings("quagga/ospfsettings")
	if err := s.Set(ctx, Values{"routerid": "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx); err != nil || f.applied != 1 || len(c.Pending()) != 0 {
		t.Errorf("settings apply: %v, applied %d, pending %v", err, f.applied, c.Pending())
	}
	n, _ := c.Entries(neighbors)
	if _, err := n.Add(ctx, Values{"address": "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if err := n.Apply(ctx); err != nil || f.applied != 2 || len(c.Pending()) != 0 {
		t.Errorf("entries apply: %v, applied %d, pending %v", err, f.applied, c.Pending())
	}
	f.applyAnswer = map[string]any{"status": "failed"}
	if _, err := n.Add(ctx, Values{"address": "192.0.2.11"}); err != nil {
		t.Fatal(err)
	}
	var ae *ErrApply
	if err := n.Apply(ctx); !errors.As(err, &ae) || len(c.Pending()) != 1 {
		t.Errorf("a failed apply must stay pending: %v, pending %v", err, c.Pending())
	}
}

// Claim: the pending list lives in one process. A new Client (the next
// provider run after a failed apply) has nothing pending, yet
// Entries.Apply and Settings.Apply must still call the endpoint; Client.Apply
// calls only what this Client saved.
func TestResourceApplyInANewProcess(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	if err := c.Apply(ctx); err != nil || f.applied != 0 {
		t.Errorf("Client.Apply with nothing pending: %v, applied %d", err, f.applied)
	}
	n, _ := c.Entries(neighbors)
	if err := n.Apply(ctx); err != nil || f.applied != 1 {
		t.Errorf("Entries.Apply in a new client: %v, applied %d, want 1", err, f.applied)
	}
	s, _ := c.Settings("quagga/ospfsettings")
	if err := s.Apply(ctx); err != nil || f.applied != 2 {
		t.Errorf("Settings.Apply in a new client: %v, applied %d, want 2", err, f.applied)
	}
	f.applyAnswer = map[string]any{"status": "failed"}
	var ae *ErrApply
	if err := n.Apply(ctx); !errors.As(err, &ae) {
		t.Errorf("a failed unconditional apply must report ErrApply: %v", err)
	}
	if len(c.Pending()) != 0 {
		t.Errorf("an unconditional apply must not invent pending entries: %v", c.Pending())
	}
}

// Claim: nested field paths ("general.enabled") build nested request
// bodies; a path that would turn a field into a container or the other way
// round is refused instead of overwriting one with the other.
func TestSetPath(t *testing.T) {
	m := map[string]any{}
	for _, p := range []string{"a.b.c", "a.b.d", "a.e", "f"} {
		if err := setPath(m, p, p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	want := map[string]any{"a": map[string]any{"b": map[string]any{"c": "a.b.c", "d": "a.b.d"}, "e": "a.e"}, "f": "f"}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %v", m)
	}
	if err := setPath(m, "f.g", "x"); err == nil {
		t.Error("a field used as a container must be refused")
	}
	if err := setPath(m, "a.b", "x"); err == nil {
		t.Error("a container overwritten by a field must be refused")
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("a refused path changed the body: %v", m)
	}
}

// Claim: every error a caller can get says what failed, where, and what
// to do, in one line, without the caller having to inspect fields. These
// messages are what a provider shows its users.
func TestErrorMessages(t *testing.T) {
	long := []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "2.0"}
	cases := []struct {
		err  error
		want []string
	}{
		{&ErrNotAvailable{Resource: "r/x", Package: ""}, []string{"r/x", "not in the capability data"}},
		{&ErrNotAvailable{Resource: "r/x", Package: "os-a", PluginsUnknown: true}, []string{"os-a", "firmware privilege"}},
		{&ErrNotAvailable{Resource: "r/x", Package: "os-a"}, []string{"os-a", "not installed"}},
		{&ErrNotAvailable{Resource: "r/x", Package: "os-a", Have: "1.0", AvailableIn: long}, []string{"1.0", "1.0, 1.1, 1.2, ..., 1.6, 2.0"}},
		{&ErrNotAvailable{Resource: "r/x", Package: "os-a", Have: "1.0"}, []string{"no known version"}},
		{&ErrFieldNotAvailable{Resource: "r/x", Field: "f"}, []string{"r/x", `"f"`}},
		{&ErrFieldNotAvailable{Resource: "r/x", Field: "f", Package: "os-a", Have: "1.0", AvailableIn: []string{"2.0"}}, []string{`"f"`, "os-a 1.0", "available in 2.0"}},
		{&ErrInvalid{Resource: "r/x", Problems: map[string]string{"b": "p2", "a": "p1"}}, []string{"r/x", "a: p1; b: p2"}},
		{&ErrValidation{Resource: "r/x", Fields: map[string]string{"f": "bad"}}, []string{"rejected", "f: bad"}},
		{&ErrValidation{Resource: "r/x", Body: `{"result":"failed"}`}, []string{"rejected", `{"result":"failed"}`}},
		{&ErrNotApplied{Resource: "r/x", ID: "u1", Diffs: []FieldDiff{{Field: "f", Sent: "1", Got: "0"}}, Hint: "h"}, []string{"r/x u1", "read back differently: f", "(h)"}},
		{&ErrApply{Endpoint: "/api/a/service/reconfigure", Answer: strings.Repeat("x", 1000)}, []string{"/api/a/service/reconfigure", "did not report ok"}},
		{&ErrDecode{Resource: "r/x", Fields: map[string]string{"f": "shape"}}, []string{"not decoded", "f: shape"}},
		{&ErrReadOnly{Resource: "r/x", Reason: "older than the data"}, []string{"writes refused", "older than the data"}},
		{&ErrWrongKind{Resource: "r/x", Kind: "entries", Want: "settings"}, []string{"entries resource, not settings"}},
		{&ErrNoOperation{Resource: "r/x", Operation: "toggle", Package: "os-a", Have: "1.0"}, []string{`"toggle"`, "os-a 1.0"}},
		{&ErrUnexpectedAnswer{Resource: "r/x", Operation: "add", ID: "u1", Answer: "?"}, []string{"r/x u1", "add"}},
		{&ErrStillExists{Resource: "r/x", ID: "u1"}, []string{"u1", "still exists"}},
		{&ErrIncompleteList{Resource: "r/x", Got: 2, Total: 5}, []string{"2 of 5"}},
	}
	for _, c := range cases {
		msg := c.err.Error()
		if !strings.HasPrefix(msg, "opnsense: ") || strings.Contains(msg, "\n") {
			t.Errorf("not a one-line opnsense error: %q", msg)
		}
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%T: %q lacks %q", c.err, msg, w)
			}
		}
		if len(msg) > 600 {
			t.Errorf("%T: message of %d bytes; answers must be truncated", c.err, len(msg))
		}
	}
}

// Claim (K6, documented on the fields): the raw answer kept in
// ErrApply.Answer and ErrUnexpectedAnswer.Answer is at most 300 bytes and
// valid UTF-8, however large the firewall's answer was, so a consumer may
// log the field as documented.
func TestRawAnswersAreTruncated(t *testing.T) {
	ctx := context.Background()
	big := strings.Repeat("ä", 2000) // two bytes per rune: a cut at an odd byte would split one
	f := newFake(t)
	f.applyAnswer = map[string]any{"status": "failed", "log": big}
	f.addAnswer = map[string]any{"result": "maybe", "log": big}
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	_, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	var ue *ErrUnexpectedAnswer
	if !errors.As(err, &ue) {
		t.Fatalf("add: %v", err)
	}
	var ae *ErrApply
	if err := n.Apply(ctx); !errors.As(err, &ae) {
		t.Fatalf("apply: %v", err)
	}
	for name, a := range map[string]string{"ErrUnexpectedAnswer.Answer": ue.Answer, "ErrApply.Answer": ae.Answer} {
		if len(a) > 300 || !utf8.ValidString(a) || !strings.HasSuffix(a, "...") {
			t.Errorf("%s: %d bytes, valid UTF-8 %v, marked as cut %v", name, len(a), utf8.ValidString(a), strings.HasSuffix(a, "..."))
		}
	}
}
