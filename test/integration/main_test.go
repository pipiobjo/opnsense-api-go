// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

//go:build integration

package integration

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestMain leaves out the tests this run does not own: with
// OPNSENSE_PACKAGES, those that need a package outside the scope (another
// VM of a parallel run tests them; scope_test.go); without OPNSENSE_MERGE,
// TestMergedGroups. With OPNSENSE_MERGE only TestMergedGroups runs (it
// needs no VM). Left-out tests do not run at all instead of skipping, so
// the skip check (tools/ci/skips.sh) sees only real skips.
func TestMain(m *testing.M) {
	flag.Parse()
	if os.Getenv("OPNSENSE_MERGE") != "" {
		_ = flag.Set("test.run", "^TestMergedGroups$")
		os.Exit(m.Run())
	}
	p := skipPattern(currentScope(), "TestMergedGroups")
	if cur := flag.Lookup("test.skip").Value.String(); cur != "" {
		if strings.Contains(cur, "/") {
			fmt.Fprintln(os.Stderr, "-skip with a subtest pattern cannot be combined with the scope's; leave it out")
			os.Exit(2)
		}
		p = cur + "|" + p
	}
	_ = flag.Set("test.skip", p)
	os.Exit(m.Run())
}

// TestMergedGroups: the per-series checks of an integration run split
// over several VMs (tools/parallel.sh). The summaries
// TestEveryVerifiedResource wrote on each VM (OPNSENSE_MERGE, files
// separated by commas) add up without a package or resource tested twice,
// the core was tested on one of them, and the tested count of the series
// reaches its floor in tested-floor.txt, as one run with every plugin
// must.
func TestMergedGroups(t *testing.T) {
	parts, err := readSummaries(strings.Split(os.Getenv("OPNSENSE_MERGE"), ","))
	if err != nil {
		t.Fatal(err)
	}
	m, err := mergeSummaries(parts)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Counts
	t.Logf("series %s, %d VMs, %d packages: tested %d resources (written and read back), %d settings only read, %d settings whose change the firewall rejected, %d skipped themselves, %d entry lists without a usable sample, %d settings not verified on this version (%d with fields not decoded, %d failed); %d read-back differences tolerated",
		m.Series, len(parts), len(m.Packages), c["tested"], c["read_only"], c["rejected"], c["skipped"], c["no_sample"], c["unverified"], c["undecodable"], c["read_failed"], c["tolerated"])
	if !slices.Contains(m.Packages, "opnsense") {
		t.Error("no VM tested the core")
	}
	if floor := testedFloor(t, m.Series); c["tested"] < floor {
		t.Errorf("tested %d resources, the floor for series %s is %d (tested-floor.txt): verification data or plugins went missing", c["tested"], m.Series, floor)
	}
}
