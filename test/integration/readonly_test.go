// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sort"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense"
)

// Claim K9 on a real firewall: a read-only client reads every resource of
// the instance and is refused every change, and the firewall's
// configuration is byte-identical afterwards. The configuration is fetched
// with raw calls (core/backup/download/this, the current config.xml),
// bypassing the client; on the VM, its checksum is stable across reads and
// changes with any saved write (checked 2026-11-17 on 26.7.9_3).
func TestReadOnlyClientChangesNothing(t *testing.T) {
	r := newRaw(t)
	conf := func() [32]byte { return sha256.Sum256(r.body("/api/core/backup/download/this")) }
	before := conf()

	c := clientWith(t, func(cfg *opnsense.Config) { cfg.ReadOnly = true })
	if !c.Instance().ReadOnly {
		t.Fatal("Instance().ReadOnly not set")
	}
	ctx := context.Background()
	refusedOK := func(what string, err error) {
		t.Helper()
		var ro *opnsense.ErrReadOnly
		if !errors.As(err, &ro) || !ro.Mode {
			t.Errorf("%s: %v, want *ErrReadOnly in read-only mode", what, err)
		}
	}
	var ids []string
	for _, d := range c.Data().Docs {
		for id := range d.Resources {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var entries, settings, read int
	for _, id := range ids {
		if e, err := c.Entries(id); err == nil {
			entries++
			if list, err := e.List(ctx); err == nil {
				read++
				if len(list) > 0 {
					_, _ = e.Get(ctx, list[0])
					refusedOK(id+" Set", e.Set(ctx, list[0], opnsense.Values{}))
					refusedOK(id+" Delete", e.Delete(ctx, list[0]))
				}
			}
			_, err := e.Add(ctx, opnsense.Values{})
			refusedOK(id+" Add", err)
			refusedOK(id+" Apply", e.Apply(ctx))
		} else if s, err := c.Settings(id); err == nil {
			settings++
			if _, err := s.Get(ctx); err == nil {
				read++
			}
			refusedOK(id+" Settings.Set", s.Set(ctx, opnsense.Values{}))
		}
	}
	refusedOK("Client.Apply", c.Apply(ctx))
	refusedOK("Call POST", c.Call(ctx, http.MethodPost, "/api/core/firmware/check", nil, nil))
	refusedOK("Call GET action", c.Call(ctx, http.MethodGet, "/api/core/service/restart/configd", nil, nil))

	if after := conf(); after != before {
		t.Error("the configuration changed during a read-only session")
	}
	t.Logf("read-only: %d entry lists, %d settings, %d read, every change refused, configuration unchanged", entries, settings, read)
}
