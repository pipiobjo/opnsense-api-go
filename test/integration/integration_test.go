// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

//go:build integration

// Package integration runs the client against a throwaway OPNsense VM
// (the action pipiobjo/opnsense-api-spec/.github/actions/testvm, or
// tools/testvm.sh start in that repository). It refuses every target other
// than 127.0.0.1.
//
//	OPNSENSE_URL=https://127.0.0.1:18443 OPNSENSE_KEYFILE=.../apikey.json \
//	OPNSENSE_CAPABILITIES=.../catalog go test -tags integration ./test/integration/
package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pipiobjo/opnsense-api-go/opnsense"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

func client(t *testing.T) *opnsense.Client {
	t.Helper()
	raw := os.Getenv("OPNSENSE_URL")
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() != "127.0.0.1" {
		t.Fatalf("OPNSENSE_URL must point at the throwaway VM on 127.0.0.1, got %q", raw)
	}
	var key struct{ Key, Secret string }
	b, err := os.ReadFile(os.Getenv("OPNSENSE_KEYFILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &key); err != nil {
		t.Fatal(err)
	}
	// the VM's certificate is self-signed and new on every boot: pin it
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: true}) // loopback only, checked above
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := opnsense.New(ctx, opnsense.Config{URL: raw, Key: key.Key, Secret: key.Secret,
		TLS: opnsense.TLS{PinSHA256: hex.EncodeToString(sum[:])}, CapabilityDir: os.Getenv("OPNSENSE_CAPABILITIES")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDetectionResolves: the VM runs a release of the data, possibly with a
// hotfix revision published after it (OPNsense ships those between
// releases). Every package resolves exactly or to the nearest data of the
// same release (a note); a guess (warning) fails.
func TestDetectionResolves(t *testing.T) {
	inst := client(t).Instance()
	t.Logf("core %s, %d plugins", inst.Core, len(inst.Plugins))
	for _, n := range inst.Notes {
		t.Logf("note: %s", n)
	}
	for name, r := range inst.Resolved.Packages {
		if r.Fragment != "" && r.Match != capability.MatchExact && r.Match != capability.MatchNearest {
			t.Errorf("%s %s: %s (%s)", name, r.Version, r.Match, r.Warning)
		}
	}
	if len(inst.Warnings) > 0 {
		t.Errorf("warnings on a release in the data: %v", inst.Warnings)
	}
}

func TestOSPFNeighborCycle(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	n, err := c.Entries("quagga/ospfsettings#neighbors.neighbor")
	if err != nil {
		t.Skip(err) // os-frr not installed
	}
	id, err := n.Add(ctx, opnsense.Values{"address": "192.0.2.10", "description": "integration", "priority": int64(7)})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Delete(ctx, id)
	got, err := n.Get(ctx, id)
	if err != nil || got["priority"] != int64(7) || got["enabled"] != true {
		t.Errorf("get: %#v %v", got, err)
	}
	if err := n.Set(ctx, id, opnsense.Values{"description": "changed", "enabled": false}); err != nil {
		t.Fatal(err)
	}
	if err := n.Toggle(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.Get(ctx, id); got["enabled"] != true {
		t.Errorf("toggle: %#v", got)
	}
	if err := n.Toggle(ctx, id, true); err != nil {
		t.Errorf("toggle to the current state: %v", err)
	}
	if err := n.Apply(ctx); err != nil {
		t.Errorf("apply: %v", err)
	}
	if err := n.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := n.Delete(ctx, id); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if err := n.Toggle(ctx, id, true); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("toggle after delete: %v", err)
	}
	if err := n.Set(ctx, id, opnsense.Values{"address": "192.0.2.11"}); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("set after delete must fail and not recreate the entry: %v", err)
	}
	if ids, _ := n.List(ctx); len(ids) != 0 {
		t.Errorf("entries left: %v", ids)
	}
	_, err = n.Add(ctx, opnsense.Values{"address": "192.0.2.12", "bogus": "x"})
	var na *opnsense.ErrFieldNotAvailable
	if !errors.As(err, &na) {
		t.Errorf("unknown field must be refused before sending: %v", err)
	}
}

func TestSettingsSetAndRestore(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	s, err := c.Settings("quagga/ospfsettings")
	if err != nil {
		t.Skip(err)
	}
	before, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, opnsense.Values{"routerid": "192.0.2.1", "costreference": int64(1000)}); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get(ctx)
	if after["routerid"] != "192.0.2.1" || after["costreference"] != int64(1000) {
		t.Errorf("settings: %#v", after)
	}
	restore := opnsense.Values{"routerid": before["routerid"], "costreference": ""}
	if v, ok := before["costreference"].(int64); ok {
		restore["costreference"] = v
	}
	if err := s.Set(ctx, restore); err != nil {
		t.Errorf("restore: %v", err)
	}
	if err := c.Apply(ctx); err != nil || len(c.Pending()) != 0 {
		t.Errorf("apply: %v, pending %v", err, c.Pending())
	}
}

// TestEveryVerifiedResource: every resource the capability data marks as
// verified on this firewall's version is exercised through the client:
//
//   - entry lists with the verified sample: add (with read-back), get, set
//     of the description (with read-back), list, delete, and the entry is
//     gone from the list afterwards;
//   - settings: get, then set of one field to its current value (with
//     read-back; nothing changes on the firewall).
//
// Apply runs at the end for every endpoint that became pending. This makes
// the client a second consumer of the spec repository's contract test
// results, and a stricter one: it compares every field it sent.
//
// A read-back difference fails the test, with one exception: on a resource
// the data marks custom-save (stored through own code that drops values
// not applying to the rest of the entry, such as DHCPv6 options on an
// interface without DHCPv6), a field the contract test did not choose on
// purpose may come back different. Each such difference is logged.
func TestEveryVerifiedResource(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	inst := c.Instance()
	var tested, skipped, tolerated int
	for pkg, d := range c.Data().Docs {
		res := inst.Resolved.Packages[pkg]
		if res == nil || res.Fragment == "" {
			continue
		}
		for id, r := range d.Resources {
			if !r.Available(res.Fragment) {
				continue
			}
			v := r.Verified[res.Fragment]
			switch r.Kind {
			case "settings":
				if v == nil || v.Read != "ok" {
					continue
				}
				// the contract test wrote it back successfully; otherwise
				// (model invalid by default, not a configuration save) the
				// client only reads it
				writable := v.Write == "ok"
				t.Run(id, func(t *testing.T) {
					s, err := c.Settings(id)
					if err != nil {
						t.Fatal(err)
					}
					cur, err := s.Get(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if !writable {
						return
					}
					name, val, ok := unchangedValue(cur, s.Fields())
					if !ok {
						t.Logf("no plain field to write back")
						return
					}
					var na *opnsense.ErrNotApplied
					var val2 *opnsense.ErrValidation
					err = s.Set(ctx, opnsense.Values{name: val})
					switch {
					case errors.As(err, &na):
						tolerated += expectedDiffs(t, na, nil)
					case errors.As(err, &val2) && !rejects(val2, name):
						// as in the contract test: the model is not valid in
						// its default state on this instance (the recorded
						// write verification may come from another core)
						t.Skipf("model not valid in its default state here: %v", err)
					case err != nil:
						t.Errorf("set %s to its current value: %v", name, err)
					}
				})
				tested++
			case "entries":
				if v == nil || v.Write != "ok" || len(v.Sample) == 0 || hasReference(v.Sample) {
					skipped++
					continue
				}
				t.Run(id, func(t *testing.T) {
					e, err := c.Entries(id)
					if err != nil {
						t.Fatal(err)
					}
					chosen := map[string]bool{}
					for _, g := range v.Generated {
						chosen[g] = true
					}
					vals := sampleValues(v.Sample, e.Fields(), r.APIFor(res.Fragment).Operations["add"])
					uid, err := e.Add(ctx, vals)
					deleted := false
					fields := e.Fields()
					// locked entries (interface assignments) refuse deletion:
					// unlock first, as the contract test does
					unlock := func() {
						if f := fields["lock"]; f != nil && f.Kind() == capability.KindBool {
							_ = e.Set(ctx, uid, opnsense.Values{"lock": false})
						}
					}
					if uid != "" {
						defer func() {
							if !deleted {
								unlock()
								if err := e.Delete(ctx, uid); err != nil {
									t.Errorf("delete: %v", err)
								}
							}
						}()
					}
					var val *opnsense.ErrValidation
					if errors.As(err, &val) {
						// the sample refers to something only the contract
						// test's instance had (a certificate, a device)
						t.Skipf("instance-specific sample: %v", err)
					}
					var na *opnsense.ErrNotApplied
					if errors.As(err, &na) && uid != "" {
						tolerated += expectedDiffs(t, na, chosen)
					} else if err != nil {
						t.Fatalf("add: %v", err)
					}
					if _, err := e.Get(ctx, uid); err != nil {
						t.Errorf("get: %v", err)
					}
					if desc := descriptionField(e.Fields(), r.APIFor(res.Fragment).Operations["set"]); desc != "" {
						// letters and digits only: description masks differ
						// (nginx rejects spaces)
						if err := e.Set(ctx, uid, opnsense.Values{desc: "integrationset2"}); errors.As(err, &na) {
							tolerated += expectedDiffs(t, na, chosen)
						} else if err != nil {
							t.Errorf("set %s: %v", desc, err)
						}
					}
					if _, ok := r.APIFor(res.Fragment).Operations["search"]; ok {
						ids, err := e.List(ctx)
						if err != nil {
							t.Errorf("list: %v", err)
						} else if !contains(ids, uid) {
							t.Errorf("list does not contain the new entry %s", uid)
						}
						unlock()
						if err := e.Delete(ctx, uid); err != nil {
							t.Fatalf("delete: %v", err)
						}
						deleted = true
						if ids, err := e.List(ctx); err == nil && contains(ids, uid) {
							t.Errorf("entry %s still listed after delete", uid)
						}
					}
				})
				tested++
			}
		}
	}
	t.Logf("tested %d resources, skipped %d entry lists (no verified sample, or the sample refers to other entries); %d read-back differences tolerated (custom-save, not chosen by the contract test)", tested, skipped, tolerated)
	for _, p := range c.Pending() {
		t.Run("apply"+p, func(t *testing.T) {
			var out map[string]any
			var he *opnsense.HTTPError
			if err := c.Call(ctx, "POST", p, nil, &out); errors.As(err, &he) && he.Status == 500 && strings.Contains(he.Body, `"errorMessage"`) {
				// the endpoint exists and the service reports why it cannot
				// run here: the test VM has no internet and no real hardware
				t.Logf("service cannot run on the test VM: %s", he.Body)
				return
			} else if err != nil {
				t.Fatal(err)
			}
			st, _ := out["status"].(string)
			res, _ := out["result"].(string)
			st, res = strings.TrimSpace(st), strings.TrimSpace(res)
			switch {
			case strings.EqualFold(st, "ok") || strings.EqualFold(res, "ok"):
			case st != "":
				// an explicit failure: services that cannot run on the test
				// VM; the client reports these as ErrApply
				t.Logf("apply reports a failure: %v", out)
			default:
				t.Errorf("unknown apply answer: %v", out)
			}
		})
	}
}

// expectedDiffs reports the differences of a read-back: those the data
// explains with custom-save on a field the contract test did not choose
// are logged and counted; every other one fails the test.
func expectedDiffs(t *testing.T, na *opnsense.ErrNotApplied, chosen map[string]bool) int {
	t.Helper()
	n := 0
	for _, d := range na.Diffs {
		if d.Cause == "custom-save" && !chosen[d.Field] {
			t.Logf("tolerated (custom-save): %s sent %q, read %q", d.Field, d.Sent, d.Got)
			n++
			continue
		}
		t.Errorf("read-back: %s sent %q, read %q (cause %q; %s)", d.Field, d.Sent, d.Got, d.Cause, na.Hint)
	}
	return n
}

// unchangedValue picks one boolean or integer field of a settings object
// with its current value, to write it back unchanged; fields the firewall
// sets itself are left out.
func unchangedValue(cur opnsense.Values, fields map[string]*capability.Field) (string, any, bool) {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := fields[n]
		if f.ServerSet() || f.WriteOnly() || f.Volatile {
			continue
		}
		switch v := cur[n].(type) {
		case bool, int64:
			return n, v, true
		}
	}
	return "", nil, false
}

// descriptionField: the entry's description field, if it has one and the
// set endpoint does not overwrite it.
func descriptionField(fields map[string]*capability.Field, set *capability.Operation) string {
	for _, n := range []string{"description", "descr"} {
		f := fields[n]
		if f == nil || f.ServerSet() || f.WriteOnly() {
			continue
		}
		if set == nil {
			return ""
		}
		if _, over := set.Overwrites(n); over {
			continue
		}
		return n
	}
	return ""
}

// rejects: the firewall's validation names the field itself (with or
// without a section prefix).
func rejects(v *opnsense.ErrValidation, field string) bool {
	for k := range v.Fields {
		if k == field || strings.HasSuffix(k, "."+field) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// sampleValues turns a verified sample into values for Add: nested
// objects become dotted paths; values the firewall sets itself, fields the
// add endpoint overwrites, empty values (often filled by the controller)
// and fields not in this version are left out.
func sampleValues(sample map[string]any, fields map[string]*capability.Field, add *capability.Operation) opnsense.Values {
	out := opnsense.Values{}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, x := range m {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			if sub, ok := x.(map[string]any); ok {
				if f := fields[name]; f == nil {
					walk(name, sub)
				}
				continue
			}
			s, ok := x.(string)
			f := fields[name]
			if !ok || s == "" || f == nil || f.ServerSet() || f.WriteOnly() {
				continue
			}
			if _, overwritten := add.Overwrites(name); overwritten {
				continue
			}
			out[name] = s
		}
	}
	walk("", sample)
	return out
}

// hasReference: a sample value that is a UUID points to an entry of the
// test instance that does not exist here.
func hasReference(sample map[string]any) bool {
	for _, x := range sample {
		s, _ := x.(string)
		for _, part := range strings.Split(s, ",") {
			if len(part) == 36 && strings.Count(part, "-") == 4 {
				return true
			}
		}
	}
	return false
}
