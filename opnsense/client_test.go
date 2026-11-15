// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

const neighbors = "quagga/ospfsettings#neighbors.neighbor"

var realData *capability.Set

func data(t *testing.T) *capability.Set {
	t.Helper()
	if realData == nil {
		s, err := capability.Load(os.DirFS("capability/testdata/catalog"))
		if err != nil {
			t.Fatal(err)
		}
		realData = s
	}
	return realData
}

func connect(t *testing.T, f *fakeFirewall, mod ...func(*Config)) (*Client, error) {
	t.Helper()
	cfg := Config{URL: f.srv.URL, Key: "key", Secret: "secret", TLS: TLS{PinSHA256: f.pin()}, Capabilities: data(t)}
	for _, m := range mod {
		m(&cfg)
	}
	return New(context.Background(), cfg)
}

func mustConnect(t *testing.T, f *fakeFirewall) *Client {
	t.Helper()
	c, err := connect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDetectExact(t *testing.T) {
	f := newFake(t)
	c := mustConnect(t, f)
	inst := c.Instance()
	if inst.Core != "26.7.9_1" || inst.Plugins["os-frr"] != "2.1" || len(inst.Plugins) != 1 {
		t.Errorf("instance: %+v", inst)
	}
	if len(inst.Warnings) != 0 {
		t.Errorf("warnings for an exact match: %v", inst.Warnings)
	}
	if r := inst.Resolved.Packages["os-frr"]; r.Match != capability.MatchExact || r.Fragment != "b04bde19061e2dec" {
		t.Errorf("os-frr: %+v", r)
	}
}

func TestDetectAssumedAndRefused(t *testing.T) {
	f := newFake(t)
	f.core = "26.7.10"
	c := mustConnect(t, f)
	if w := strings.Join(c.Instance().Warnings, "|"); !strings.Contains(w, "assuming 26.7.9_1") {
		t.Errorf("want a warning about the assumed core, got %q", w)
	}
	if _, err := connect(t, f, func(c *Config) { c.UnknownVersion = Refuse }); err == nil {
		t.Error("Refuse must fail for an unknown core")
	}
}

func TestTLSPinAndAuth(t *testing.T) {
	f := newFake(t)
	_, err := connect(t, f, func(c *Config) { c.TLS.PinSHA256 = strings.Repeat("ab", 32) })
	if err == nil || !strings.Contains(err.Error(), "does not match the pin") {
		t.Errorf("wrong pin: %v", err)
	}
	_, err = connect(t, f, func(c *Config) { c.TLS = TLS{} })
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("self-signed without pin or CA must fail: %v", err)
	}
	c, err := connect(t, f, func(c *Config) { c.TLS = TLS{InsecureSkipVerify: true} })
	if err != nil || c.Instance().Warnings[0] != InsecureWarning {
		t.Errorf("InsecureSkipVerify must connect and warn: %v", err)
	}
	if _, err := connect(t, f, func(c *Config) { c.TLS.InsecureSkipVerify = true }); err == nil {
		t.Error("InsecureSkipVerify together with a pin must be refused")
	}
	_, err = connect(t, f, func(c *Config) { c.Secret = "wrong" })
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong secret: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("the secret must not appear in the error")
	}
	_, err = connect(t, f, func(c *Config) { c.URL = strings.Replace(f.srv.URL, "https", "http", 1) })
	if err == nil {
		t.Error("http:// must be refused")
	}
}

func TestEntriesCycle(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, err := c.Entries(neighbors)
	if err != nil {
		t.Fatal(err)
	}
	id, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "lab", "priority": int64(5)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := n.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := Values{"address": "192.0.2.10", "description": "lab", "priority": int64(5), "enabled": true, "pollinterval": nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("get:\n got %#v\nwant %#v", got, want)
	}
	if err := n.Set(ctx, id, Values{"enabled": false}); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.Get(ctx, id); got["enabled"] != false || got["description"] != "lab" {
		t.Errorf("partial set changed other fields or did not apply: %#v", got)
	}
	ids, err := n.List(ctx)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Errorf("list: %v %v", ids, err)
	}
	if p := c.Pending(); len(p) != 1 || p[0] != "/api/quagga/service/reconfigure" {
		t.Errorf("pending: %v", p)
	}
	if err := c.Apply(ctx); err != nil || f.applied != 1 || len(c.Pending()) != 0 {
		t.Errorf("apply: %v, applied %d, pending %v", err, f.applied, c.Pending())
	}
	if err := n.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	if err := n.Delete(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	// OPNsense would create the entry again under this UUID
	if err := n.Set(ctx, id, Values{"address": "192.0.2.11"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("set of a deleted entry must fail, not recreate it: %v", err)
	}
	if len(f.nbrs) != 0 {
		t.Errorf("the deleted entry was recreated: %v", f.nbrs)
	}
}

func TestNothingIsSentThatTheVersionDoesNotHave(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	before := len(f.calls)
	_, err := n.Add(ctx, Values{"address": "192.0.2.10", "bogus": "x"})
	var na *ErrFieldNotAvailable
	if !errors.As(err, &na) || na.Field != "bogus" {
		t.Errorf("unknown field: %v", err)
	}
	_, err = n.Add(ctx, Values{"address": "192.0.2.10", "priority": "high", "enabled": "yes"})
	var inv *ErrInvalid
	if !errors.As(err, &inv) || inv.Problems["enabled"] == "" {
		t.Errorf("invalid values: %v", err)
	}
	if len(f.calls) != before {
		t.Errorf("requests were sent despite local errors: %v", f.calls[before:])
	}
	// required values are left to the firewall (the model's "required" is
	// not reliable for add)
	_, err = n.Add(ctx, Values{"description": "no address"})
	var val *ErrValidation
	if !errors.As(err, &val) || val.Fields["address"] == "" {
		t.Errorf("missing required field: %v", err)
	}
}

// A field that exists in another version only: the OSPF area of os-frr
// 1.x is free text, in 2.x a relation. Here the resource exists, but a
// field of another version must be named with the versions that have it.
func TestFieldOfAnotherVersion(t *testing.T) {
	f := newFake(t)
	f.plugins["os-frr"] = "1.45"
	f.core = "25.7"
	c := mustConnect(t, f)
	s, err := c.Settings("quagga/ospfsettings")
	if err != nil {
		t.Fatal(err)
	}
	have := s.Fields()
	all := data(t).Docs["os-frr"].Resources["quagga/ospfsettings"].Fields
	var missing string
	for name := range all {
		if have[name] == nil {
			missing = name
			break
		}
	}
	if missing == "" {
		t.Skip("no field missing in 1.45")
	}
	err = s.Set(context.Background(), Values{missing: "1"})
	var na *ErrFieldNotAvailable
	if !errors.As(err, &na) || len(na.AvailableIn) == 0 || na.Have != "1.45" {
		t.Errorf("field %s of another version: %v", missing, err)
	}
}

func TestResourceNotAvailable(t *testing.T) {
	f := newFake(t)
	delete(f.plugins, "os-frr")
	c := mustConnect(t, f)
	_, err := c.Entries(neighbors)
	var na *ErrNotAvailable
	if !errors.As(err, &na) || na.Package != "os-frr" || na.Have != "" {
		t.Errorf("not installed: %v", err)
	}
	if _, err := c.Entries("nothing/here#x"); !errors.As(err, &na) || na.Package != "" {
		t.Errorf("unknown resource: %v", err)
	}
	f2 := newFake(t)
	if _, err := mustConnect(t, f2).Settings(neighbors); err == nil {
		t.Error("an entry list is not a settings resource")
	}
}

func TestReadBackCatchesWhatTheServerIgnored(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.dropSets["description"] = true // the server says "saved" but keeps the old value
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "lost"})
	var na *ErrNotApplied
	if !errors.As(err, &na) || id == "" || len(na.Diffs) != 1 || na.Diffs[0].Field != "description" || na.Diffs[0].Sent != "lost" {
		t.Errorf("read-back: id %q, %v", id, err)
	}
}

func TestValidationFromTheFirewall(t *testing.T) {
	ctx := context.Background()
	c := mustConnect(t, newFake(t))
	n, _ := c.Entries(neighbors)
	_, err := n.Add(ctx, Values{"address": "not-an-ip"})
	var v *ErrValidation
	if !errors.As(err, &v) || !strings.Contains(v.Fields["address"], "valid network") {
		t.Errorf("validation: %v", err)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := mustConnect(t, f)
	s, err := c.Settings("quagga/ospfsettings")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, Values{"enabled": true, "routerid": "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != true || got["routerid"] != "192.0.2.1" || got["costreference"] != nil {
		t.Errorf("settings: %#v", got)
	}
	if _, ok := got["neighbors.neighbor"]; ok {
		t.Error("entry lists inside the model are not settings fields")
	}
	if f.ospf["logadjacencychanges"] != "0" {
		t.Error("a partial set must not touch other fields")
	}
}

func TestAutoApply(t *testing.T) {
	f := newFake(t)
	c, err := connect(t, f, func(c *Config) { c.AutoApply = true })
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.Settings("quagga/ospfsettings")
	if err := s.Set(context.Background(), Values{"enabled": true}); err != nil {
		t.Fatal(err)
	}
	if f.applied != 1 || len(c.Pending()) != 0 {
		t.Errorf("auto apply: applied %d, pending %v", f.applied, c.Pending())
	}
}
