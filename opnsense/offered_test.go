// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Claim (runtime references): OfferedOptions lists what the firewall
// offers for a field of a new entry (its empty-entry template), including
// options it fills in at runtime such as certificates, with their labels
// and without the empty choice; a field that is not a selection and a
// field the version lacks are errors, not an empty list.
func TestOfferedOptions(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	// the template's address as a selection the firewall fills at runtime
	// (shape as stunnel servercert on 26.7.10: refid -> certificate name)
	f.raw = map[string]string{"GET /api/quagga/ospfsettings/getNeighbor": `{"neighbor":{"enabled":"1","description":"",` +
		`"address":{"":{"value":"none","selected":1},"6a1f0c2b9d3e4":{"value":"Web GUI TLS certificate","selected":0},"5b2e":{"value":"other","selected":0}},` +
		`"pollinterval":"","priority":""}}`}
	c := mustConnect(t, f)
	n, _ := c.Entries(neighbors)
	got, err := n.OfferedOptions(ctx, "address")
	if err != nil {
		t.Fatal(err)
	}
	want := []Option{{Value: "5b2e", Label: "other"}, {Value: "6a1f0c2b9d3e4", Label: "Web GUI TLS certificate"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("offered %+v, want %+v", got, want)
	}
	if _, err := n.OfferedOptions(ctx, "description"); err == nil {
		t.Error("a text field offered options; want an error")
	}
	var na *ErrFieldNotAvailable
	if _, err := n.OfferedOptions(ctx, "nosuchfield"); !errors.As(err, &na) {
		t.Errorf("unknown field: %v, want ErrFieldNotAvailable", err)
	}
}
