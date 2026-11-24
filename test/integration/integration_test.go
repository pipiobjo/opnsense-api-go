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
//
// OPNSENSE_PLUGINS=all says every plugin was requested for the VM: then a
// resource of a plugin that is missing fails the tests that need it
// instead of skipping them. TESTVM_SLOW (default 1) is how many times
// slower the VM is than with hardware virtualisation (software emulation:
// 6, as tools/testvm.sh); request timeouts are stretched by it.
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
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pipiobjo/opnsense-api-go/opnsense"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

func client(t *testing.T) *opnsense.Client {
	t.Helper()
	return clientWith(t, nil)
}

// clientWith is client with changes to the configuration (mod may be nil).
func clientWith(t *testing.T, mod func(*opnsense.Config)) *opnsense.Client {
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
	f := slow(t)
	ctx, cancel := context.WithTimeout(context.Background(), f*time.Minute)
	defer cancel()
	cfg := opnsense.Config{URL: raw, Key: key.Key, Secret: key.Secret,
		TLS: opnsense.TLS{PinSHA256: hex.EncodeToString(sum[:])}, CapabilityDir: os.Getenv("OPNSENSE_CAPABILITIES"),
		Timeout: f * opnsense.DefaultTimeout, ApplyTimeout: f * opnsense.DefaultApplyTimeout}
	if mod != nil {
		mod(&cfg)
	}
	c, err := opnsense.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// slow is the factor TESTVM_SLOW (default 1) by which the VM is slower
// than with hardware virtualisation.
func slow(t *testing.T) time.Duration {
	t.Helper()
	v := os.Getenv("TESTVM_SLOW")
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("TESTVM_SLOW=%q: want a whole number of at least 1", v)
	}
	return time.Duration(n)
}

// missing ends a test whose resource is not on the VM: a failure when
// every plugin was requested (OPNSENSE_PLUGINS=all), since the plugin then
// failed to install and its resources went untested; a skip otherwise.
func missing(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("OPNSENSE_PLUGINS") == "all" {
		t.Fatalf("every plugin was requested, but: %v", err)
	}
	t.Skip(err)
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
		missing(t, err) // os-frr not installed
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
		missing(t, err) // os-frr not installed
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
//   - settings the contract test wrote: get, then one boolean field set to
//     the other value and back (each with read-back), so a stored write is
//     told from an ignored one; settings it only read: get.
//
// Apply runs at the end for every endpoint that became pending; only the
// endpoints in apply-failures.json (services that cannot run on the
// isolated VM, per series) may fail. This makes the client a second
// consumer of the spec repository's contract test results, and a stricter
// one: it compares every field it sent.
//
// A read-back difference fails the test, with one exception: on a resource
// the data marks custom-save (stored through own code that drops values
// not applying to the rest of the entry, such as DHCPv6 options on an
// interface without DHCPv6), a field the contract test did not choose on
// purpose, and that this test did not change on purpose, may come back
// different. Each such difference is logged.
//
// Only subtests that ran to the end without failing count as tested;
// skipped ones are counted apart. The tested count must reach the floor of
// the series in tested-floor.txt, so lost verification data cannot leave
// a green run that tested nothing.
func TestEveryVerifiedResource(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	inst := c.Instance()
	// tested: ran and passed; readOnly: settings the contract test only
	// read (passed); skippedRun: a subtest that skipped itself; noSample:
	// entry lists without a usable sample; unverified: settings whose read
	// was not verified on this version (the contract test found a known
	// gap, or has no result), of them undecodable: read with *ErrDecode,
	// readFailed: the read failed
	// rejected: settings whose changed field the firewall's validation
	// refused (nothing was written, so not tested)
	var tested, readOnly, skippedRun, noSample, unverified, undecodable, readFailed, tolerated, rejected int
	count := func(passed, skipped, onlyRead, wasRejected bool) {
		switch {
		case skipped:
			skippedRun++
		case passed && wasRejected:
			rejected++
		case passed && onlyRead:
			readOnly++
		case passed:
			tested++
		}
	}
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
				if v == nil || v.Read != capability.StatusOK {
					// not verified, so not written; still read through the
					// client, and what fails is counted and logged: the
					// contract test found the answer's shape different
					// (known-gap) or has no result, so a failure here is
					// expected data, not a client fault
					status := "no result"
					if v != nil {
						status = string(v.Read)
					}
					t.Run("unverified/"+id, func(t *testing.T) {
						s, err := c.Settings(id)
						if err != nil {
							t.Fatal(err)
						}
						_, err = s.Get(ctx)
						var de *opnsense.ErrDecode
						switch {
						case errors.As(err, &de):
							undecodable++
							t.Logf("contract test read: %s; not decoded: %v", status, de)
						case err != nil:
							readFailed++
							t.Logf("contract test read: %s; read failed: %v", status, err)
						}
					})
					unverified++
					continue
				}
				// the contract test wrote it back successfully; otherwise
				// (model invalid by default, not a configuration save) the
				// client only reads it
				writable := v.Write == capability.StatusOK
				var passed, skipped, wasRejected bool
				t.Run(id, func(t *testing.T) {
					defer func() { passed, skipped = !t.Failed(), t.Skipped() }()
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
					// a different value, then the original again: writing the
					// current value back could not tell a stored write from an
					// ignored one
					cands := flippable(cur, s.Fields())
					if len(cands) == 0 {
						t.Skip("no boolean field to change and restore")
					}
					var na *opnsense.ErrNotApplied
					var val2 *opnsense.ErrValidation
					// a resource stored through own code (custom-save) may
					// ignore a field that does not apply in its current state:
					// then the next boolean field is tried; only a field that
					// is stored counts
					var name string
					var val bool
					for i, cand := range cands {
						name, val = cand.name, cand.val
						err = s.Set(ctx, opnsense.Values{name: !val})
						if !errors.As(err, &na) || !ignored(na, name) {
							break
						}
						t.Logf("%s=%v not stored (custom-save); trying the next boolean field", name, !val)
						if i == len(cands)-1 {
							t.Skipf("the firewall's own save code ignored every boolean field (%d)", len(cands))
						}
					}
					switch {
					case errors.As(err, &na):
						// the changed field itself must read back as sent
						tolerated += expectedDiffs(t, na, map[string]bool{name: true})
					case errors.As(err, &val2) && !rejects(val2, name):
						// as in the contract test: the model is not valid in
						// its default state on this instance (the recorded
						// write verification may come from another core)
						t.Skipf("model not valid in its default state here: %v", err)
					case errors.As(err, &val2):
						// the other value is not allowed in this state (a
						// dependency between fields): nothing was written, so
						// this resource is counted apart, not as tested
						t.Logf("%s=%v rejected by the firewall's validation, nothing written: %v", name, !val, err)
						wasRejected = true
						return
					case err != nil:
						t.Errorf("set %s to %v: %v", name, !val, err)
					}
					if err := s.Set(ctx, opnsense.Values{name: val}); errors.As(err, &na) {
						tolerated += expectedDiffs(t, na, map[string]bool{name: true})
					} else if err != nil {
						t.Errorf("restore %s to %v: %v", name, val, err)
					}
				})
				count(passed, skipped, !writable, wasRejected)
			case "entries":
				if v == nil || v.Write != capability.StatusOK || len(v.Sample) == 0 || hasReference(v.Sample) {
					noSample++
					continue
				}
				var passed, skipped bool
				t.Run(id, func(t *testing.T) {
					defer func() { passed, skipped = !t.Failed(), t.Skipped() }()
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
						// only a value that refers to something on the contract
						// test's instance (a certificate, an interface, another
						// entry) may be rejected here; any other rejection is
						// a fault in the client or the data
						if refersToInstance(val, e.Fields()) {
							t.Skipf("instance-specific sample: %v", err)
						}
						t.Fatalf("add rejected for values that do not refer to other objects: %v", err)
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
						} else if !slices.Contains(ids, uid) {
							t.Errorf("list does not contain the new entry %s", uid)
						}
						rowsAgree(t, ctx, e, uid, vals)
						unlock()
						if err := e.Delete(ctx, uid); err != nil {
							t.Fatalf("delete: %v", err)
						}
						deleted = true
						if ids, err := e.List(ctx); err == nil && slices.Contains(ids, uid) {
							t.Errorf("entry %s still listed after delete", uid)
						}
						_, canSet := r.APIFor(res.Fragment).Operations["set"]
						goneStaysGone(t, ctx, e, uid, canSet)
					}
				})
				count(passed, skipped, false, false)
			}
		}
	}
	t.Logf("tested %d resources (written and read back), %d settings only read (the contract test did not write them), %d settings whose change the firewall rejected (nothing written), %d skipped themselves, %d entry lists without a usable sample, %d settings not verified on this version (read through the client: %d with fields not decoded, %d failed); %d read-back differences tolerated (custom-save, not chosen)",
		tested, readOnly, rejected, skippedRun, noSample, unverified, undecodable, readFailed, tolerated)
	if floor := testedFloor(t, inst.Resolved.Series); tested < floor {
		t.Errorf("tested %d resources, the floor for series %s is %d (tested-floor.txt): verification data or plugins went missing", tested, inst.Resolved.Series, floor)
	}
	// apply through the client: every pending endpoint once; afterwards only
	// those that failed may still be pending
	t.Run("apply", func(t *testing.T) {
		before := c.Pending()
		err := c.Apply(ctx)
		allowed := applyFailures(t, inst.Resolved.Series)
		failed := map[string]bool{}
		for _, e := range unwrap(err) {
			var he *opnsense.HTTPError
			var ea *opnsense.ErrApply
			var path, what string
			switch {
			case errors.As(e, &he) && he.Status == 500 && strings.Contains(he.Body, `"errorMessage"`):
				// the service reports why it cannot run
				path, what = he.Path, he.Body
			case errors.As(e, &ea):
				path, what = ea.Endpoint, ea.Answer
			default:
				t.Errorf("apply: %v", e)
				continue
			}
			failed[path] = true
			switch a, ok := allowed[path]; {
			case ok && strings.Contains(what, a.Match):
				t.Logf("apply %s failed as expected on the test VM (%s): %s", path, a.Reason, what)
			case ok:
				t.Errorf("apply %s failed differently than apply-failures.json expects (match %q): %s", path, a.Match, what)
			default:
				t.Errorf("apply %s failed and is not in apply-failures.json for series %s: %s", path, inst.Resolved.Series, what)
			}
		}
		// an entry whose apply worked is out of date: red, so the watchdog
		// reports it after 7 days if nobody removes it
		for p := range allowed {
			if slices.Contains(before, p) && !failed[p] {
				t.Errorf("apply %s is listed in apply-failures.json but worked on series %s: remove the entry (or narrow its series)", p, inst.Resolved.Series)
			}
		}
		for _, p := range c.Pending() {
			if !failed[p] {
				t.Errorf("%s still pending although it did not fail", p)
			}
		}
		t.Logf("applied %d endpoints, %d could not run on the test VM", len(before), len(failed))
	})
}

// rowsAgree: the new entry is in Rows with the values Get returns, for
// every field both show, and Find with the values Add sent that the rows
// show (as Get returns them) finds it.
func rowsAgree(t *testing.T, ctx context.Context, e *opnsense.Entries, uid string, sent opnsense.Values) {
	t.Helper()
	got, err := e.Get(ctx, uid)
	if err != nil {
		t.Errorf("get: %v", err)
		return
	}
	rows, err := e.Rows(ctx)
	if err != nil {
		t.Errorf("rows: %v", err)
		return
	}
	i := slices.IndexFunc(rows, func(r opnsense.Row) bool { return r.ID == uid })
	if i < 0 {
		t.Errorf("rows lack the new entry %s", uid)
		return
	}
	for name, rv := range rows[i].Values {
		if gv, ok := got[name]; ok && !reflect.DeepEqual(rv, gv) {
			t.Errorf("rows: %s is %#v, get says %#v", name, rv, gv)
		}
	}
	match := opnsense.Values{}
	for name := range sent {
		_, shown := rows[i].Values[name]
		if v, ok := got[name]; ok && shown {
			match[name] = v
		}
	}
	found, err := e.Find(ctx, match)
	if err != nil {
		t.Errorf("find by %v: %v", keys(match), err)
	} else if !slices.ContainsFunc(found, func(r opnsense.Row) bool { return r.ID == uid }) {
		t.Errorf("find by %v does not return the new entry", keys(match))
	}
}

// goneStaysGone: after a delete the entry reads as not found, and a set
// (where the list has one) is refused instead of creating it again under
// the same ID.
func goneStaysGone(t *testing.T, ctx context.Context, e *opnsense.Entries, uid string, canSet bool) {
	t.Helper()
	if _, err := e.Get(ctx, uid); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("get after delete: %v, want ErrNotFound", err)
	}
	if !canSet {
		return
	}
	if err := e.Set(ctx, uid, opnsense.Values{}); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("set after delete: %v, want ErrNotFound", err)
		if ids, _ := e.List(ctx); slices.Contains(ids, uid) {
			t.Errorf("set after delete created %s again", uid)
			_ = e.Delete(ctx, uid)
		}
	}
}

func keys(v opnsense.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unwrap lists the errors joined by errors.Join (or the error itself).
func unwrap(err error) []error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, unwrap(e)...)
		}
		return out
	}
	return []error{err}
}

// refersToInstance: every rejected field holds a value that points to
// something of the contract test's instance: a relation to other entries,
// or an option list filled at run time (certificates, interfaces).
func refersToInstance(v *opnsense.ErrValidation, fields map[string]*capability.Field) bool {
	if len(v.Fields) == 0 {
		return false
	}
	for name := range v.Fields {
		f := fields[name]
		if f == nil {
			return false
		}
		runtimeOptions := f.Base == "BaseListField" && len(f.Options) == 0
		for _, g := range f.Gaps {
			runtimeOptions = runtimeOptions || g == "options-dynamic"
		}
		if len(f.Relations) == 0 && !runtimeOptions {
			return false
		}
	}
	return true
}

type flip struct {
	name string
	val  bool
}

// flippable: the boolean fields of a settings object with their current
// values, to change and restore, in name order; fields the firewall sets
// itself are left out.
func flippable(cur opnsense.Values, fields map[string]*capability.Field) []flip {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []flip
	for _, n := range names {
		f := fields[n]
		if f.ServerSet || f.WriteOnly || f.Volatile || len(f.Gaps) > 0 {
			continue
		}
		if b, ok := cur[n].(bool); ok {
			out = append(out, flip{n, b})
		}
	}
	return out
}

// ignored: the read-back shows that the firewall's own save code
// (custom-save) did not store this field.
func ignored(na *opnsense.ErrNotApplied, field string) bool {
	for _, d := range na.Diffs {
		if d.Field == field && d.Cause == opnsense.CauseCustomSave {
			return true
		}
	}
	return false
}

// expectedDiffs reports the differences of a read-back: those the data
// explains with custom-save on a field the contract test did not choose
// are logged and counted; every other one fails the test.
func expectedDiffs(t *testing.T, na *opnsense.ErrNotApplied, chosen map[string]bool) int {
	t.Helper()
	n := 0
	for _, d := range na.Diffs {
		if d.Cause == opnsense.CauseCustomSave && !chosen[d.Field] {
			t.Logf("tolerated (custom-save): %s sent %q, read %q", d.Field, d.Sent, d.Got)
			n++
			continue
		}
		t.Errorf("read-back: %s sent %q, read %q (cause %q; %s)", d.Field, d.Sent, d.Got, d.Cause, na.Hint)
	}
	return n
}

// descriptionField: the entry's description field, if it has one and the
// set endpoint does not overwrite it.
func descriptionField(fields map[string]*capability.Field, set *capability.Operation) string {
	for _, n := range []string{"description", "descr"} {
		f := fields[n]
		if f == nil || f.ServerSet || f.WriteOnly {
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

// sampleValues turns a verified sample into values for Add: nested
// objects become dotted paths; values the firewall sets itself, fields the
// add endpoint overwrites, empty values (often filled by the controller)
// and fields not in this version are left out; write-only fields get a
// test value.
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
			if ok && f != nil && f.WriteOnly {
				// the firewall never returns a write-only value (a
				// password), so the sample cannot hold it: send a value of
				// letters and digits, which the client does not compare
				out[name] = "Integration1pw"
				continue
			}
			if !ok || s == "" || f == nil || f.ServerSet {
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
