// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package mutation keeps the proof that the client's most important checks
// can fail (requirement Q1(c)). Each case breaks one rule in the source and
// runs the test that guards it; the test must fail. The source files are
// not touched: the broken copy is given to the compiler with go's
// -overlay. The same technique as opnsense-api-spec's internal/mutation.
package mutation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type mutant struct {
	name     string // the rule that is broken
	file     string // relative to the module root
	from, to string // exact text, must occur once in file
	pkg      string // package with the guarding test
	test     string // -run pattern
}

// The checks whose silent loss would hurt most: a write that did not take
// effect is an error (F6: result check, read-back, existence), read-only
// mode (F7, both layers), trust in the connection (Q2: pin, CA, path),
// no values in error texts, and what the client tells a consumer about
// secrets and verification.
var mutants = []mutant{
	{"rejected entry set not reported", "opnsense/resource.go",
		`if err := b.result(resp, "saved", "set", id); err != nil {`,
		`if err := b.result(resp, "saved", "set", id); err != nil && false {`,
		"./opnsense/", "^TestSetRejectedByTheFirewall$"},
	{"rejected settings set not reported", "opnsense/resource.go",
		`if err := b.result(resp, "saved", "set", ""); err != nil {`,
		`if err := b.result(resp, "saved", "set", ""); err != nil && false {`,
		"./opnsense/", "^TestSetRejectedByTheFirewall$"},
	{"failed read-back counted as success", "opnsense/resource.go",
		`return fmt.Errorf("opnsense: %s: reading back after the write: %w", b.id, err)`,
		`return nil`,
		"./opnsense/", "^TestReadBackFailureIsAnError$"},
	{"read-back does not compare values", "opnsense/resource.go",
		`if !ok || !f.SameWire(sent[name], got) {`,
		`if !ok {`,
		"./opnsense/", "^TestReadBackCatchesWhatTheServerIgnored$"},
	{"existence by any search row, not the ID", "opnsense/resource.go",
		"if r.id == id {\n\t\t\treturn obj, order, err",
		"if r.id != \"\" {\n\t\t\treturn obj, order, err",
		"./opnsense/", "^TestTemplateControllerMatchesTheID$"},
	{"a write trusts the remembered list", "opnsense/resource.go",
		`if cached && b.c.listedRecently(b.id, id) {`,
		`if b.c.listedRecently(b.id, id) {`,
		"./opnsense/", "^TestExistenceSearchIsReusedByGet$"},
	{"writes run in parallel by default", "opnsense/client.go",
		"if !c.cfg.ParallelWrites {\n\t\tkey = \"write\"\n\t}",
		"",
		"./opnsense/", "^TestWritesAreSerialisedByDefault$"},
	{"delete not confirmed", "opnsense/resource.go",
		`confirm = &ErrStillExists{Resource: b.id, ID: id}`,
		`confirm = nil`,
		"./opnsense/", "^TestDeleteIsConfirmed$"},
	{"read-only mode not checked by the API", "opnsense/client.go",
		"if b.c.cfg.ReadOnly {\n\t\treturn &ErrReadOnly{",
		"if false {\n\t\treturn &ErrReadOnly{",
		"./opnsense/", "^TestReadOnlyMode$"},
	{"read-only mode not checked by the transport", "internal/transport/transport.go",
		"if t.ro {\n\t\treturn fmt.Errorf(\"%w: POST %s\", ErrWriteRefused, path)",
		"if false {\n\t\treturn fmt.Errorf(\"%w: POST %s\", ErrWriteRefused, path)",
		"./internal/transport/", "^TestReadOnlyTransport$"},
	{"certificate pin not compared", "internal/transport/transport.go",
		`if !bytes.Equal(got[:], want) {`,
		`if !bytes.Equal(got[:], want) && false {`,
		"./opnsense/", "^TestTLSPinAndAuth$"},
	{"configured CA extends the system roots", "internal/transport/transport.go",
		`pool := x509.NewCertPool()`,
		`pool, _ := x509.SystemCertPool()`,
		"./opnsense/", "^TestCAReplacesSystemRoots$"},
	{"dot segments allowed in API paths", "internal/transport/transport.go",
		`if seg == "" || seg == "." || seg == ".." {`,
		`if seg == "" {`,
		"./internal/transport/", "^TestCheckPath$"},
	{"firewall messages in ErrValidation.Error", "opnsense/errors.go",
		`strings.Join(names, ", "))`,
		`joinMap(e.Fields))`,
		"./opnsense/", "^TestValuesNeverInErrorMessages$"},
	{"secret rule without its type filter", "opnsense/capability/secret.go",
		`if !slices.Contains(secretBases, f.Base) && !slices.Contains(secretTypes, f.Type) {`,
		`if !slices.Contains(secretBases, f.Base) && !slices.Contains(secretTypes, f.Type) && false {`,
		"./opnsense/capability/", "^TestSecretWords$"},
	{"settings echo counted as write-verified", "opnsense/fields.go",
		`return in.Kind != "settings" || slices.Contains(v.Steps, capability.StepReadBackRestore)`,
		`return true`,
		"./opnsense/", "^TestWriteVerified$"},
	{"newer core data used for an older core", "opnsense/capability/resolve.go",
		`if CompareVersions(refs[i].Version, v) <= 0 {`,
		`if true {`,
		"./opnsense/capability/", "^TestResolveCoreNeverNewer$"},
	{"an ordered list compared as a set (DEV-1)", "opnsense/capability/values.go",
		"if !f.Ordered() {",
		"if true {",
		"./opnsense/capability/", "^TestListFields$"},
	{"the answer's list order not used on read-back (DEV-1)", "opnsense/resource.go",
		"if got, err = f.WireOrdered(raw, order[name]); err != nil {",
		"if got, err = f.WireOrdered(raw, nil); err != nil || order == nil && false {",
		"./opnsense/", "^TestListOrderIsReadAndCompared$"},
}

// Claim (Q1(c)): every check in the table above fails when its rule is
// removed. A mutant that survives means the test lost its power; an
// anchor that no longer matches means the code changed and the table must
// follow it (the failure says which).
func TestMutantsAreKilled(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test once per mutant")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	gobin := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		gobin = "go"
	}
	for _, m := range mutants {
		t.Run(m.name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, m.file))
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(src), m.from); n != 1 {
				t.Fatalf("anchor found %d times in %s (want 1); update the mutant to the current code: %q", n, m.file, m.from)
			}
			dir := t.TempDir()
			mutated := filepath.Join(dir, filepath.Base(m.file))
			if err := os.WriteFile(mutated, []byte(strings.Replace(string(src), m.from, m.to, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]map[string]string{"Replace": {filepath.Join(root, m.file): mutated}})
			ov := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(ov, overlay, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(gobin, "test", "-count=1", "-overlay", ov, "-run", m.test, m.pkg)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOFLAGS=")
			out, err := cmd.CombinedOutput()
			switch {
			case err == nil:
				t.Errorf("mutant survived: %s still passes with %q", m.test, m.to)
			case strings.Contains(string(out), "[build failed]") || strings.Contains(string(out), "[setup failed]"):
				t.Errorf("mutant does not compile; break the rule, not the build:\n%s", out)
			case !strings.Contains(string(out), "--- FAIL"):
				t.Errorf("go test failed without a failing test:\n%s", out)
			}
		})
	}
}
