// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"testing"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
)

// FuzzCheckID: an entry ID the client accepts, from a caller or from a
// firewall's search answer, can never change the path it is appended to.
// Seeds are IDs seen on real firewalls and classic traversal attempts.
func FuzzCheckID(f *testing.F) {
	for _, s := range []string{
		"00000000-0000-4000-8000-000000000001", "wan", "bogons", "lockout_0", "opt1",
		"d41d8cd98f00b204e9800998ecf8427e", "..", ".", "../x", "a/b", "%2e%2e", "a\x00", "a b", "a?b", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if checkID(id) != nil {
			return
		}
		for _, base := range []string{"/api/m/c/getItem/", "/api/m/c/delItem/"} {
			if err := transport.CheckPath(base + id); err != nil {
				t.Fatalf("accepted id %q makes an invalid path: %v", id, err)
			}
		}
	})
}
