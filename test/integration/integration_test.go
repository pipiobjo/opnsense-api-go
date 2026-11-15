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
	"testing"
	"time"

	"github.com/pipiobjo/opnsense-api-go/opnsense"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

func client(t *testing.T) *opnsense.Client {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := opnsense.New(ctx, opnsense.Config{URL: raw, Key: key.Key, Secret: key.Secret,
		TLS: opnsense.TLS{PinSHA256: hex.EncodeToString(sum[:])}, CapabilityDir: os.Getenv("OPNSENSE_CAPABILITIES")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDetectionIsExact(t *testing.T) {
	inst := client(t).Instance()
	t.Logf("core %s, %d plugins", inst.Core, len(inst.Plugins))
	for name, r := range inst.Resolved.Packages {
		if r.Fragment != "" && r.Match != capability.MatchExact {
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
		t.Skip(err) // os-frr not installed
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
	if err := n.Delete(ctx, id); err != nil {
		t.Fatal(err)
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
		t.Skip(err)
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
}
