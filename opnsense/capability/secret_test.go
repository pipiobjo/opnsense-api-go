// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/secret/golden.txt (and, with SECRET_DATA=<unpacked catalog>, fields.tsv.gz)")

// Claim (P1, M7 of the spec's requirements): the secret rule marks the
// credential fields a name list of password/secret/key alone misses, and
// leaves out integers, booleans and options whose names only look alike.
// The cases are real fields of the published data.
func TestSecretWords(t *testing.T) {
	text := func(typ string) *Field { return &Field{Type: typ, Base: typ} }
	secret := map[string]*Field{
		"wpa.passphrase":                     text("TextField"),       // core wireless
		"otp_seed":                           text("TextField"),       // core auth/user (TOTP seed)
		"community":                          text("StrictTextField"), // os-net-snmp
		"acme_ruckus_pass":                   text("TextField"),       // os-acme-client
		"dns_pleskxml_pass":                  text("TextField"),
		"dns_wedos_wapipass":                 text("TextField"),
		"dns_dnsexit_auth_pass":              text("TextField"),
		"dns_infoblox_credentials":           text("TextField"),
		"acme_synology_dsm_otpcode":          text("TextField"),
		"privkey":                            text("Base64Field"),
		"ddns_domain_key_secret":             text("Base64Field"),
		"auth_server_shared_secret":          text("TextField"),
		"dns_cf_key":                         text("TextField"),
		"wep.keys":                           text("TextField"),
		"general.token":                      text("TextField"), // os-cloudflared
		"dns_kas_authdata":                   text("TextField"),
		"dns_nederhost_key":                  text("TextField"),
		"apikeys":                            {Type: "ApiKeyField", Base: "BaseField"},
		"password":                           {Type: "UpdateOnlyTextField", Base: "UpdateOnlyTextField", WriteOnly: true},
		"anything":                           {Type: "TextField", Base: "TextField", WriteOnly: true},
		"control_port_password_hashed":       text("TextField"),
		"general.output.elasticsearch.token": text("TextField"),
	}
	notSecret := map[string]*Field{
		"in_pass_b":                         text("IntegerField"), // firewall alias statistics
		"general.mmonitRegisterCredentials": text("BooleanField"), // monit: a switch
		"out_pass_b":                        text("IntegerField"),
		"bypass":                            text("BooleanField"), // ids
		"useauthsecret":                     text("BooleanField"),
		"passthrough_networks":              {Type: "NetworkField", Base: "BaseSetField"},
		"wpa_group_rekey":                   text("IntegerField"),
		"pass":                              {Type: "OptionField", Base: "BaseListField", Options: []Option{{Value: "pass"}}},
		"tls_key":                           {Type: "ModelRelationField", Base: "BaseListField", Relations: []Relation{{Source: "x"}}},
		"pubkey":                            text("Base64Field"),
		"publickey":                         text("TextField"),
		"remote_ssh_host_key":               text("TextField"),
		"sftp_filename_key":                 text("TextField"),
		"keyfingerprint":                    text("TextField"),
		"ddns_domain_key_name":              text("TextField"),
		"acme_proxmoxbs_tokenid":            text("TextField"),
		"dns_sl_token_lifetime":             text("TextField"),
		"authorizedkeys":                    text("TextField"),
		"smtpauth_user":                     text("TextField"),
		"fcgi_pass_header":                  text("TextField"),
		"passivehealthunhealthys":           text("TextField"),
		"description":                       text("TextField"),
		"secrets":                           {Type: "TextField", Base: "TextField", Multiple: true},
	}
	for name, f := range secret {
		if !f.Secret(name) {
			t.Errorf("%s (%s) is a secret", name, f.Type)
		}
	}
	for name, f := range notSecret {
		if f.Secret(name) {
			t.Errorf("%s (%s) is not a secret", name, f.Type)
		}
	}
	var nilField *Field
	if nilField.Secret("password") {
		t.Error("a missing field is not a secret")
	}
}

// Claim: the rule's result over one complete published data state is the
// reviewed list in testdata/secret/golden.txt. fields.tsv.gz holds every
// field variant of that state (package, resource, field, type, base,
// multiple, write_only, number of options and relations), so the test needs
// no download. A changed rule changes the list; review the difference and
// rewrite it with -update. For a newer data state:
//
//	SECRET_DATA=<unpacked catalog> go test -run TestSecretGolden -update ./opnsense/capability/
func TestSecretGolden(t *testing.T) {
	dir := filepath.Join("testdata", "secret")
	if src := os.Getenv("SECRET_DATA"); src != "" {
		if !*update {
			t.Fatal("SECRET_DATA is only used with -update")
		}
		s, err := Load(os.DirFS(src))
		if err != nil {
			t.Fatal(err)
		}
		writeFieldsTSV(t, filepath.Join(dir, "fields.tsv.gz"), s)
	}
	id, rows := readFieldsTSV(t, filepath.Join(dir, "fields.tsv.gz"))
	marked := map[string]bool{}
	for _, r := range rows {
		if r.f.Secret(r.name) {
			marked[r.pkg+"\t"+r.res+"\t"+r.name] = true
		}
	}
	got := slices.Sorted(func(yield func(string) bool) {
		for k := range marked {
			if !yield(k) {
				return
			}
		}
	})
	text := fmt.Sprintf("# Fields capability.Field.Secret marks in data_id %s (%d of %d fields).\n"+
		"# Package, resource, field. Generated by TestSecretGolden -update; review every change.\n%s\n",
		id, len(got), countFields(rows), strings.Join(got, "\n"))
	golden := filepath.Join(dir, "golden.txt")
	if *update {
		if err := os.WriteFile(golden, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != text {
		wl := strings.Split(string(want), "\n")
		gl := strings.Split(text, "\n")
		for _, l := range gl {
			if !slices.Contains(wl, l) {
				t.Errorf("marked now, not in golden.txt: %q", l)
			}
		}
		for _, l := range wl {
			if !slices.Contains(gl, l) {
				t.Errorf("in golden.txt, not marked now: %q", l)
			}
		}
	}
	// the review's examples stay in the list
	for _, must := range []string{"opnsense\tinterfaces/wireless_settings#clone\twpa.passphrase",
		"opnsense\tauth/user#user\totp_seed", "os-net-snmp\tnetsnmp/general\tcommunity",
		"os-acme-client\tacmeclient/actions#actions.action\tacme_ruckus_pass",
		"os-acme-client\tacmeclient/validations#validations.validation\tdns_infoblox_credentials"} {
		if !marked[must] {
			t.Errorf("not marked: %q", must)
		}
	}
	for k := range marked {
		if strings.HasSuffix(k, "\tin_pass_b") || strings.HasSuffix(k, "\tbypass") {
			t.Errorf("marked: %q", k)
		}
	}
}

type fieldRow struct {
	pkg, res, name string
	f              *Field
}

func countFields(rows []fieldRow) int {
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.pkg+"\t"+r.res+"\t"+r.name] = true
	}
	return len(seen)
}

func writeFieldsTSV(t *testing.T, path string, s *Set) {
	t.Helper()
	lines := map[string]bool{}
	for pkg, d := range s.Docs {
		for id, r := range d.Resources {
			for name, vs := range r.Fields {
				for _, f := range vs {
					lines[strings.Join([]string{pkg, id, name, f.Type, f.Base, strconv.FormatBool(f.Multiple),
						strconv.FormatBool(f.WriteOnly), strconv.Itoa(len(f.Options)), strconv.Itoa(len(f.Relations))}, "\t")] = true
				}
			}
		}
	}
	sorted := make([]string, 0, len(lines))
	for l := range lines {
		sorted = append(sorted, l)
	}
	sort.Strings(sorted)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	fmt.Fprintf(zw, "# data_id %s\n%s\n", s.Catalog.DataID, strings.Join(sorted, "\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFieldsTSV(t *testing.T, path string) (string, []fieldRow) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var id string
	var rows []fieldRow
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "# data_id "); ok {
			id = v
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 9 {
			t.Fatalf("%s: bad line %q", path, line)
		}
		nopt, _ := strconv.Atoi(c[7])
		nrel, _ := strconv.Atoi(c[8])
		f := &Field{Type: c[3], Base: c[4], Multiple: c[5] == "true", WriteOnly: c[6] == "true",
			Options: make([]Option, nopt), Relations: make([]Relation, nrel)}
		rows = append(rows, fieldRow{c[0], c[1], c[2], f})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if id == "" || len(rows) == 0 {
		t.Fatalf("%s: no data_id or no fields", path)
	}
	return id, rows
}
