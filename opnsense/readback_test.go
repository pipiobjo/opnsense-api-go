// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Toggle confirms the state by reading the entry, not by the answer.
func TestToggleReadsBack(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.toggleIgnored = true
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	var na *ErrNotApplied
	if err := n.Toggle(ctx, id, false); !errors.As(err, &na) || len(na.Diffs) != 1 || na.Diffs[0].Field != "enabled" {
		t.Errorf("a toggle that changed nothing must be ErrNotApplied on enabled: %v", err)
	}
	if len(c.Pending()) == 0 {
		t.Error("a toggle was sent: its apply endpoint must be pending")
	}
}

// A get of a deleted entry that answers the complete blank template is
// not an entry: Get says ErrNotFound.
func TestGetFullTemplateIsNotFound(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.fullTemplate = true
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	if v, err := n.Get(ctx, "00000000-0000-4000-8000-0000000000aa"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v %v", v, err)
	}
	// an entry that really has only default values is still found
	id, err := n.Add(ctx, Values{"address": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	f.nbrs[id]["address"] = "" // now exactly as blank as the template
	if _, err := n.Get(ctx, id); err != nil {
		t.Errorf("an existing entry equal to the template: %v", err)
	}
}

// Fields the firewall does not store (volatile) are refused before
// sending; transformed fields must at least be present after a write.
func TestVolatileRefusedTransformedChecked(t *testing.T) {
	ctx := context.Background()
	s, err := capability.Load(os.DirFS("capability/testdata/catalog")) // private copy
	if err != nil {
		t.Fatal(err)
	}
	frag := frrFragment(t, s)
	r := s.Docs["os-frr"].Resources[neighbors]
	r.FieldFor("description", frag).Volatile = true
	f := newFake(t)
	c, err := connect(t, f, func(cfg *Config) { cfg.Capabilities = s })
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.Entries(neighbors)
	var inv *ErrInvalid
	if _, err := n.Add(ctx, Values{"address": "192.0.2.10", "description": "x"}); !errors.As(err, &inv) || inv.Problems["description"] == "" {
		t.Errorf("a volatile field must be refused: %v", err)
	}

	s2, _ := capability.Load(os.DirFS("capability/testdata/catalog"))
	r2 := s2.Docs["os-frr"].Resources[neighbors]
	for _, op := range r2.APIFor(frag).Operations {
		op.Transformed = []string{"description"}
	}
	f2 := newFake(t)
	f2.dropSets["description"] = true // stored as "" instead of in another form
	c2, err := connect(t, f2, func(cfg *Config) { cfg.Capabilities = s2 })
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := c2.Entries(neighbors)
	var na *ErrNotApplied
	if _, err := n2.Add(ctx, Values{"address": "192.0.2.10", "description": "x"}); !errors.As(err, &na) {
		t.Errorf("a transformed field that came back empty must be ErrNotApplied: %v", err)
	}
}

// With AutoApply the read-back comes first; a failing apply does not hide
// a value the firewall dropped. Both errors are returned.
func TestAutoApplyAfterReadBack(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.dropSets["description"] = true
	f.applyAnswer = map[string]any{"status": "failed"}
	c, err := connect(t, f, func(cfg *Config) { cfg.AutoApply = true })
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.Entries(neighbors)
	_, err = n.Add(ctx, Values{"address": "192.0.2.10", "description": "lost"})
	var na *ErrNotApplied
	var ea *ErrApply
	if !errors.As(err, &na) || !errors.As(err, &ea) {
		t.Errorf("want both ErrNotApplied and ErrApply: %v", err)
	}
}
