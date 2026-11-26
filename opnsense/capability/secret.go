// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"slices"
	"strings"
)

// Secret reports whether the field (name is its path, e.g.
// "general.password") holds a secret: a value that must not be shown in a
// plan, a log or a tool's output. OPNsense marks few secrets as such, so
// this is the one place that decides, for every consumer (the provider's
// Sensitive attributes, an MCP server's masking):
//
//   - a write-only field (the firewall never returns it) is a secret;
//   - otherwise only a single free-text value can be one: a field whose
//     base type is a text or base64 field, without options or relations
//     (a boolean "useauthsecret" or an integer "in_pass_b" is not);
//   - of those, the last part of the name decides: it contains one of
//     secretWords, ends in one of secretEnds, and contains none of
//     notSecretWords.
//
// The rule errs towards hiding: names such as zabbix's item "key" or the
// "key" of a user's API key (auth/user_api_key, the public half; the
// firewall stores the secret half only as a hash and never returns it)
// are marked although they are no secret. Hiding a value costs a reader
// little; an exception per field would be a list someone must keep up,
// so there is none. testdata/secret/golden.txt lists
// every field it marks in one published data state; a change of the rule
// shows there.
func (f *Field) Secret(name string) bool {
	if f == nil {
		return false
	}
	if f.WriteOnly {
		return true
	}
	if f.Multiple || len(f.Options) > 0 || len(f.Relations) > 0 {
		return false
	}
	if !slices.Contains(secretBases, f.Base) && !slices.Contains(secretTypes, f.Type) {
		return false
	}
	n := strings.ToLower(name[strings.LastIndex(name, ".")+1:])
	for _, w := range notSecretWords {
		if strings.Contains(n, w) {
			return false
		}
	}
	for _, w := range notSecretEnds {
		if strings.HasSuffix(n, w) {
			return false
		}
	}
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	for _, w := range secretEnds {
		if strings.HasSuffix(n, w) {
			return true
		}
	}
	return false
}

// The vocabulary of Field.Secret.
var (
	// base types that hold one free-text value
	secretBases = []string{"TextField", "StrictTextField", "Base64Field", "UpdateOnlyTextField"}
	// field types that hold credentials whatever their base (the API keys
	// of a user)
	secretTypes = []string{"ApiKeyField"}
	// anywhere in the name
	secretWords = []string{"password", "passwd", "passphrase", "secret", "psk", "token",
		"otp", "seed", "community", "credential", "privkey", "privatekey", "private_key",
		"authdata", "auth_cookie"}
	// at the end of the name: "basicauthpass", "acme_ruckus_pass",
	// "dns_wedos_wapipass"; "apikey", "dns_cf_key", "wep.keys"
	secretEnds = []string{"pass", "key", "keys"}
	// public keys, file names, fingerprints, algorithms and sizes, lifetimes
	notSecretWords = []string{"pub", "fingerprint", "filename", "_host_key", "authorized",
		"chmod", "hashkey", "counter", "lifetime", "algo", "location"}
	// names, IDs, modes, types and user names belong to a secret, but are
	// none
	notSecretEnds = []string{"name", "id", "mode", "type", "user", "header"}
)
