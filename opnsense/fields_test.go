// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"errors"
	"os"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Claim (README): Info describes a resource as a provider needs it, from
// the data: write-only, server-set and runtime-required fields, other
// resources on the same stored data, the verification result. The values
// are copies: changing them changes nothing in the client.
func TestInfo(t *testing.T) {
	s, err := capability.Load(os.DirFS("capability/testdata/catalog")) // private copy
	if err != nil {
		t.Fatal(err)
	}
	frag := frrFragment(t, s)
	r := s.Docs["os-frr"].Resources[neighbors]
	fd := r.FieldFor("description", frag)
	fd.WriteOnly = true
	r.FieldFor("priority", frag).ServerSet = true
	r.SharedWith = []string{"quagga/other"}
	f := newFake(t)
	c, err := connect(t, f, func(cfg *Config) { cfg.Capabilities = s })
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.Entries(neighbors)
	in := n.Info()
	if in.ID != neighbors || in.Kind != "entries" || in.Package != "os-frr" || in.Version != "2.1" || in.ReadOnly != "" {
		t.Errorf("info: %+v", in)
	}
	if len(in.SharedWith) != 1 || in.SharedWith[0] != "quagga/other" {
		t.Errorf("SharedWith: %v", in.SharedWith)
	}
	if in.Verified == nil {
		t.Fatal("Verified: nil, the test data has a result for this version")
	}
	addr, desc, prio := in.Fields["address"], in.Fields["description"], in.Fields["priority"]
	if !addr.RuntimeRequired || addr.Type != "NetworkField" || addr.Kind != capability.KindString {
		t.Errorf("address (runtime-required in the data): %+v", addr)
	}
	if !desc.WriteOnly || desc.RuntimeRequired || !prio.ServerSet || prio.Kind != capability.KindInt {
		t.Errorf("description %+v, priority %+v", desc, prio)
	}
	if !desc.Secret || addr.Secret {
		t.Errorf("Secret: a write-only field is one, an address is none: description %+v, address %+v", desc, addr)
	}
	if in.Fields["enabled"].Kind != capability.KindBool {
		t.Errorf("enabled: %+v", in.Fields["enabled"])
	}

	// copies: changing what was returned changes nothing
	in.SharedWith[0] = "x"
	in.Verified.RuntimeRequired[0] = "x"
	n.Fields()["address"].Type = "x"
	n.Fields()["priority"].ServerSet = false
	again := n.Info()
	if again.SharedWith[0] != "quagga/other" || again.Fields["address"].Type != "NetworkField" || !again.Fields["address"].RuntimeRequired {
		t.Errorf("Info or Fields returned shared data: %+v", again)
	}
	var inv *ErrInvalid
	if err := n.Check(Values{"priority": 5}); !errors.As(err, &inv) {
		t.Errorf("a server-set field must stay refused after changing a returned copy: %v", err)
	}

	ro, err := connect(t, f, func(cfg *Config) { cfg.Capabilities = s; cfg.ReadOnly = true })
	if err != nil {
		t.Fatal(err)
	}
	rn, _ := ro.Entries(neighbors)
	if rn.Info().ReadOnly == "" {
		t.Error("Info().ReadOnly must say why writes are refused in read-only mode")
	}
}

// Claim (README): Check runs the checks of a write without sending: a
// provider can refuse a plan before apply.
func TestCheck(t *testing.T) {
	f := newFake(t)
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	s, _ := c.Settings("quagga/ospfsettings")
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	if err := n.Check(Values{"address": "192.0.2.10", "enabled": true, "priority": 3}); err != nil {
		t.Errorf("valid entry: %v", err)
	}
	if err := s.Check(Values{"routerid": "192.0.2.1", "enabled": false}); err != nil {
		t.Errorf("valid settings: %v", err)
	}
	var inv *ErrInvalid
	var fna *ErrFieldNotAvailable
	if err := n.Check(Values{"enabled": "yes"}); !errors.As(err, &inv) {
		t.Errorf("bad boolean: %v", err)
	}
	if err := n.Check(Values{"nosuchfield": "x"}); !errors.As(err, &fna) {
		t.Errorf("unknown field: %v", err)
	}
	if err := s.Check(Values{"enabled": 1}); !errors.As(err, &inv) {
		t.Errorf("settings: integer for a boolean: %v", err)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if len(calls) != 0 {
		t.Errorf("Check sent requests: %v", calls)
	}
	ro, err := connect(t, f, func(cfg *Config) { cfg.ReadOnly = true })
	if err != nil {
		t.Fatal(err)
	}
	rn, _ := ro.Entries(neighbors)
	if err := rn.Check(Values{"address": "192.0.2.10"}); !errors.Is(err, ErrWriteRefused) {
		t.Errorf("Check in read-only mode: %v", err)
	}
}
