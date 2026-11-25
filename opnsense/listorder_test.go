// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Claim (DEV-1 of the review of 2026-11-24): a list field whose order the
// firewall keeps (os-frr OSPF area ranges, an AsList NetworkField) is read
// in the order of the answer, and a write that comes back in another order
// is ErrNotApplied; the same elements in the same order are no difference.
func TestListOrderIsReadAndCompared(t *testing.T) {
	f := newFake(t)
	const answer = `{"area":{"id":"0.0.0.1","ranges":{"198.51.100.0/24":{"value":"198.51.100.0/24","selected":1},"192.0.2.0/24":{"value":"192.0.2.0/24","selected":1}}}}`
	f.raw = map[string]string{
		"GET /api/quagga/ospfsettings/getArea/" + probeID: `[]`,
		"GET /api/quagga/ospfsettings/getArea/a1":         answer,
		"POST /api/quagga/ospfsettings/setArea/a1":        `{"result":"saved"}`,
	}
	c := mustConnect(t, f)
	e, err := c.Entries("quagga/ospfsettings#areas.area")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := e.Get(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/24", "192.0.2.0/24"}; !reflect.DeepEqual(got["ranges"], want) {
		t.Errorf("ranges %#v, want the answer's order %q", got["ranges"], want)
	}
	if err := e.Set(ctx, "a1", Values{"ranges": []string{"198.51.100.0/24", "192.0.2.0/24"}}); err != nil {
		t.Errorf("same order: %v", err)
	}
	var na *ErrNotApplied
	if err := e.Set(ctx, "a1", Values{"ranges": []string{"192.0.2.0/24", "198.51.100.0/24"}}); !errors.As(err, &na) {
		t.Errorf("another order read back must be ErrNotApplied, got %v", err)
	}
}
