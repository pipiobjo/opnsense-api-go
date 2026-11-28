// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"os"
	"strings"
	"testing"
)

func i64(v int64) *int64 { return &v }

// probeSet: one settings resource with probed fields, as the spec
// publishes them.
func probeSet(port *Field, rejected []string) *Set {
	all := In{All: true}
	port.In = all
	return &Set{Docs: map[string]*Doc{"opnsense": {Resources: map[string]*Resource{"x/settings": {
		Kind: "settings", In: []string{"h1"},
		Fields: map[string][]*Field{
			"general.port":    {port},
			"general.enabled": {{In: all, Type: "BooleanField", Base: "BooleanField", Required: true}},
			"general.mode": {{In: all, Type: "OptionField", Base: "BaseListField", ReadShape: "select",
				Options: []Option{{Value: "a"}, {Value: "b"}}}},
			"general.name": {{In: all, Type: "TextField", Base: "TextField", Limits: &Limits{Pattern: `[a-z]+`}}},
			// a rule over several fields: published verdicts were reached in
			// a context in which the field's own values decide
			"general.peer": {{In: all, Type: "NetworkField", Base: "BaseSetField", Gaps: []string{GapModelValidation},
				Limits: &Limits{Format: &ValueFormat{Kind: FormatNetwork, Netmask: "forbidden"}}}},
			// options decided at run time: still one value, not a list
			"general.iface": {{In: all, Type: "InterfaceField", Base: "BaseListField", ReadShape: "select"}},
		},
		Verified: map[string]*ResVerify{"h1": {Probe: StatusOK, Probes: map[string]*Verdicts{
			"general.port":    {Accepted: []string{"", "1", "65535"}, Rejected: rejected},
			"general.enabled": {Accepted: []string{"0", "1"}, Rejected: []string{"", "2"}},
			"general.mode":    {Accepted: []string{"", "a", "b"}, Rejected: []string{"x", "a,b"}},
			"general.name":    {Accepted: []string{"abc"}, Rejected: []string{"abc1", "1abc"}},
			"general.peer":    {Accepted: []string{"192.0.2.10"}, Rejected: []string{"192.0.2.0/24", "x"}},
			"general.iface":   {Accepted: []string{"lan"}, Rejected: []string{"lan,wan"}},
		}}},
	}}}}}
}

func TestReplayProbes(t *testing.T) {
	port := &Field{Type: "IntegerField", Base: "IntegerField", Limits: &Limits{Minimum: i64(1), Maximum: i64(65535)}}
	r := probeSet(port, []string{"0", "65536", "contract-test"}).ReplayProbes()
	if len(r.Disagree) > 0 || r.Checked != 23 || r.Skipped != 0 || r.Resources != 1 {
		t.Fatalf("%+v", r)
	}
	// the data without the maximum: the check lets 65536 pass, the
	// firewall refused it
	port = &Field{Type: "IntegerField", Base: "IntegerField", Limits: &Limits{Minimum: i64(1)}}
	r = probeSet(port, []string{"0", "65536"}).ReplayProbes()
	if len(r.Disagree) != 1 || !strings.Contains(r.Disagree[0], `general.port="65536": the firewall rejected it`) {
		t.Errorf("%+v", r)
	}
}

// TestPublishedProbes replays every probe of the capability data: the
// client's value check and the firewall agree on every value (spec ADR
// 0017). With OPNSENSE_CAPABILITIES (ci.yml, job data) on the pinned data,
// which must contain probes; else on the test data.
func TestPublishedProbes(t *testing.T) {
	dir := os.Getenv("OPNSENSE_CAPABILITIES")
	if dir == "" {
		dir = "testdata/catalog"
	}
	s, err := Load(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	r := s.ReplayProbes()
	t.Logf("%s: %d resources, %d probes agree, %d not replayed (no field variant)", dir, r.Resources, r.Checked, r.Skipped)
	for _, d := range r.Disagree {
		t.Error(d)
	}
	if os.Getenv("OPNSENSE_CAPABILITIES") != "" && r.Checked == 0 {
		t.Error("the pinned data has no probes: nothing was compared")
	}
}
