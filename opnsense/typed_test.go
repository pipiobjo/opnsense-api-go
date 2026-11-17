// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"testing"
)

// A plugin older than all data of its series: reads work, every kind of
// write is refused with ErrReadOnly before anything is sent.
func TestReadOnlyPackageRefusesWrites(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.plugins["os-frr"] = "0.1" // older than every os-frr version in the test data
	c := mustConnect(t, f)
	n, err := c.Entries(neighbors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.List(ctx); err != nil {
		t.Errorf("reading must work: %v", err)
	}
	f.nbrs["00000000-0000-4000-8000-000000000099"] = map[string]string{"enabled": "1", "address": "192.0.2.9", "description": "", "pollinterval": "", "priority": ""}
	id := "00000000-0000-4000-8000-000000000099"
	var ro *ErrReadOnly
	if _, err := n.Add(ctx, Values{"address": "192.0.2.10"}); !errors.As(err, &ro) || ro.Package != "os-frr" || ro.Have != "0.1" {
		t.Errorf("add: %v", err)
	}
	if err := n.Set(ctx, id, Values{"description": "x"}); !errors.As(err, &ro) {
		t.Errorf("set: %v", err)
	}
	if err := n.Toggle(ctx, id, false); !errors.As(err, &ro) {
		t.Errorf("toggle: %v", err)
	}
	if err := n.Delete(ctx, id); !errors.As(err, &ro) {
		t.Errorf("delete: %v", err)
	}
	s, _ := c.Settings("quagga/ospfsettings")
	if err := s.Set(ctx, Values{"routerid": "192.0.2.1"}); !errors.As(err, &ro) {
		t.Errorf("settings set: %v", err)
	}
	for _, call := range f.calls {
		if call == "POST /api/quagga/ospfsettings/addNeighbor" || call == "POST /api/quagga/ospfsettings/set" {
			t.Errorf("a write reached the firewall: %s", call)
		}
	}
}

// Errors a provider must tell apart are typed, not only text.
func TestTypedErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("wrong kind", func(t *testing.T) {
		c := mustConnect(t, newFake(t))
		var e *ErrWrongKind
		if _, err := c.Settings(neighbors); !errors.As(err, &e) || e.Kind != "entries" || e.Want != "settings" {
			t.Errorf("%v", err)
		}
	})

	t.Run("add answered without an id: the entry may exist, apply pending", func(t *testing.T) {
		f := newFake(t)
		f.addNoID = true
		c := mustConnect(t, f)
		n, _ := c.Entries(neighbors)
		_, err := n.Add(ctx, Values{"address": "192.0.2.10"})
		var e *ErrUnexpectedAnswer
		if !errors.As(err, &e) || e.Operation != "add" {
			t.Errorf("%v", err)
		}
		if len(c.Pending()) == 0 {
			t.Error("the entry was probably created: its apply endpoint must be pending")
		}
	})

	t.Run("delete answered but the entry stays", func(t *testing.T) {
		f := newFake(t)
		f.delKeeps = true
		c := mustConnect(t, f)
		n, _ := c.Entries(neighbors)
		id, _ := n.Add(ctx, Values{"address": "192.0.2.10"})
		var e *ErrStillExists
		if err := n.Delete(ctx, id); !errors.As(err, &e) || e.ID != id {
			t.Errorf("%v", err)
		}
	})

	t.Run("newer series", func(t *testing.T) {
		f := newFake(t)
		f.core = "27.1"
		var e *ErrSeriesNotInData
		if _, err := connect(t, f); !errors.As(err, &e) || !e.Newer {
			t.Errorf("%v", err)
		}
	})
}
