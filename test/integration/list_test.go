// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

//go:build integration

package integration

import (
	"context"
	"reflect"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// TestListFieldsKeepOrder (DEV-1 of the review of 2026-11-24): list fields
// without "multiple" are lists, with the separator of the data, and keep
// the order written. Two elements are written out of sorted order and must
// read back in that order, without ErrNotApplied from the read-back:
// a firewall alias (content, separator newline) and the DNS servers of a
// Kea subnet (an AsList NetworkField, separator comma).
func TestListFieldsKeepOrder(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	for _, tc := range []struct {
		resource, field string
		base            opnsense.Values
		list            []string
		sep             string
	}{
		{"firewall/alias#aliases.alias", "content",
			opnsense.Values{"name": "itlist", "type": "host", "description": "integration"},
			[]string{"192.0.2.2", "192.0.2.1"}, "\n"},
		{"kea/dhcpv4#subnets.subnet4", "option_data.domain_name_servers",
			opnsense.Values{"subnet": "192.0.2.0/24", "description": "integration"},
			[]string{"192.0.2.53", "192.0.2.1"}, ","},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			e, err := c.Entries(tc.resource)
			if err != nil {
				missing(t, err)
			}
			info := e.Info().Fields[tc.field]
			if info.Kind != capability.KindList {
				t.Fatalf("%s is %v in the data, want a list", tc.field, info.Kind)
			}
			v := opnsense.Values{tc.field: tc.list}
			for k, x := range tc.base {
				v[k] = x
			}
			id, err := e.Add(ctx, v) // reads back: a reordered list is ErrNotApplied
			if err != nil {
				t.Fatal(err)
			}
			defer e.Delete(ctx, id)
			got, err := e.Get(ctx, id)
			if err != nil || !reflect.DeepEqual(got[tc.field], tc.list) {
				t.Errorf("get: %#v, %v; want %q", got[tc.field], err, tc.list)
			}
			rev := []string{tc.list[1], tc.list[0]}
			if err := e.Set(ctx, id, opnsense.Values{tc.field: rev}); err != nil {
				t.Errorf("set in the other order: %v", err)
			}
			if got, _ := e.Get(ctx, id); !reflect.DeepEqual(got[tc.field], rev) {
				t.Errorf("after set: %#v, want %q", got[tc.field], rev)
			}
			if err := e.Delete(ctx, id); err != nil {
				t.Error(err)
			}
		})
	}
}
