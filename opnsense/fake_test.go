// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeFirewall behaves like OPNsense 26.7.9_1 with os-frr 2.1 for the OSPF
// settings and neighbors, as recorded from a test VM on 2026-11-15:
// unknown keys are ignored silently, an unknown UUID reads as [], a missing
// endpoint is HTTP 404, a GET with a Content-Type is HTTP 400, and a set
// with an unknown UUID creates the entry under that UUID.
type fakeFirewall struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	core     string
	plugins  map[string]string
	ospf     map[string]string            // settings, flat
	nbrs     map[string]map[string]string // uuid -> neighbor
	next     int
	dropSets map[string]bool // fields the "server" accepts but does not store
	calls    []string
	applied  int

	// failure modes
	applyAnswer   map[string]any  // answer of reconfigure (default {"status":"ok"})
	applyGate     chan struct{}   // if set, reconfigure waits for it (without holding mu)
	applyStart    chan struct{}   // closed when reconfigure is entered
	infoStatus    int             // HTTP status of firmware/info (default 200)
	delKeeps      bool            // del answers "deleted" but keeps the entry
	addNoID       bool            // add stores the entry but answers "saved" without a uuid
	fullTemplate  bool            // get of an unknown UUID answers the complete blank template
	toggleIgnored bool            // toggle answers as if it switched, but changes nothing
	encodeSets    map[string]bool // neighbor fields stored base64-encoded (nginx error pages)
	delSilent     bool            // del answers with an empty body (os-wol on 26.7.9)
	oddField      string          // this neighbor field is returned in an unexpected shape
	searchPage    int             // rows per page when rowCount is not -1 (0: all)
	writeOnly     map[string]bool // neighbor fields stored but read back as "" (UpdateOnlyTextField)
	virtualRows   []string        // ids of rows search adds without counting them in total (26.1 d_nat anti-lockout rules)
}

func newFake(t *testing.T) *fakeFirewall {
	f := &fakeFirewall{t: t, core: "26.7.9_1", plugins: map[string]string{"os-frr": "2.1"},
		ospf: map[string]string{"enabled": "0", "routerid": "", "costreference": "", "logadjacencychanges": "0",
			"carp_demote": "0", "originate": "0", "originatealways": "0", "originatemetric": ""},
		nbrs: map[string]map[string]string{}, dropSets: map[string]bool{}}
	// EnableHTTP2 must be set before the server starts, as on OPNsense,
	// whose web server answers HTTP/2
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// pin is the SHA-256 of the fake's self-signed certificate.
func (f *fakeFirewall) pin() string {
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func (f *fakeFirewall) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/quagga/service/reconfigure" && f.applyGate != nil {
		close(f.applyStart)
		<-f.applyGate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if k, s, ok := r.BasicAuth(); !ok || k != "key" || s != "secret" {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"status":401,"message":"Authentication Failed"}`)
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("Content-Type") != "" {
		w.WriteHeader(400)
		return
	}
	var body map[string]any
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("POST %s: body is not JSON: %v", r.URL.Path, err)
		}
	}
	p := r.URL.Path
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case p == "/api/core/firmware/info" && f.infoStatus != 0:
		w.WriteHeader(f.infoStatus)
	case p == "/api/core/firmware/status":
		reply(map[string]any{"product": map[string]any{"product_version": f.core}})
	case p == "/api/core/firmware/info":
		var plugins []map[string]string
		for n, v := range f.plugins {
			plugins = append(plugins, map[string]string{"name": n, "version": v, "installed": "1"})
		}
		plugins = append(plugins, map[string]string{"name": "os-tayga", "version": "1.5_1", "installed": "0"})
		reply(map[string]any{"product_version": f.core, "product_id": "opnsense",
			"package": []map[string]string{{"name": "opnsense", "version": f.core, "installed": "1"},
				{"name": "os-acme-client", "version": "4.10", "installed": "0"}}, "plugin": plugins})
	case p == "/api/quagga/ospfsettings/get":
		reply(map[string]any{"ospf": f.ospfObject()})
	case p == "/api/quagga/ospfsettings/set":
		in, _ := body["ospf"].(map[string]any)
		if v, ok := in["enabled"].(string); ok && v != "0" && v != "1" {
			reply(map[string]any{"result": "failed", "validations": map[string]any{"ospf.enabled": "Value should be a boolean (0,1)."}})
			return
		}
		for k, v := range in {
			if _, known := f.ospf[k]; known && !f.dropSets[k] { // unknown keys: ignored
				f.ospf[k] = fmt.Sprint(v)
			}
		}
		reply(map[string]any{"result": "saved"})
	case p == "/api/quagga/ospfsettings/addNeighbor":
		in, _ := body["neighbor"].(map[string]any)
		if ip, _ := in["address"].(string); net.ParseIP(ip) == nil {
			reply(map[string]any{"result": "failed", "validations": map[string]any{"neighbor.address": "Please specify a valid network segment or IP address."}})
			return
		}
		f.next++
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", f.next)
		n := map[string]string{"enabled": "1", "description": "", "address": "", "pollinterval": "", "priority": ""}
		f.store(n, in)
		f.nbrs[id] = n
		if f.addNoID {
			reply(map[string]any{"result": "saved"})
			return
		}
		reply(map[string]any{"result": "saved", "uuid": id})
	case p == "/api/quagga/ospfsettings/getNeighbor":
		// without a UUID: the blank template of a new entry, as getBase answers
		reply(map[string]any{"neighbor": blankNeighbor()})
	case strings.HasPrefix(p, "/api/quagga/ospfsettings/getNeighbor/"):
		n := f.nbrs[strings.TrimPrefix(p, "/api/quagga/ospfsettings/getNeighbor/")]
		if n == nil && f.fullTemplate {
			reply(map[string]any{"neighbor": blankNeighbor()})
			return
		}
		if n == nil {
			reply([]any{})
			return
		}
		out := map[string]any{}
		for k, v := range n {
			out[k] = v
			if f.writeOnly[k] {
				out[k] = "" // OPNsense never returns an UpdateOnlyTextField's value
			}
		}
		if f.oddField != "" {
			out[f.oddField] = map[string]any{"unexpected": []any{1, 2}}
		}
		reply(map[string]any{"neighbor": out})
	case strings.HasPrefix(p, "/api/quagga/ospfsettings/toggleNeighbor/"):
		n := f.nbrs[strings.TrimPrefix(p, "/api/quagga/ospfsettings/toggleNeighbor/")]
		if n == nil {
			reply(map[string]any{"result": "failed"})
			return
		}
		if f.toggleIgnored {
			reply(map[string]any{"result": map[string]string{"1": "Disabled", "0": "Enabled"}[n["enabled"]], "changed": true})
			return
		}
		if n["enabled"] == "1" {
			n["enabled"] = "0"
			reply(map[string]any{"result": "Disabled", "changed": true})
		} else {
			n["enabled"] = "1"
			reply(map[string]any{"result": "Enabled", "changed": true})
		}
	case strings.HasPrefix(p, "/api/quagga/ospfsettings/setNeighbor/"):
		id := strings.TrimPrefix(p, "/api/quagga/ospfsettings/setNeighbor/")
		in, _ := body["neighbor"].(map[string]any)
		n := f.nbrs[id]
		if n == nil {
			// as the real firewall: an unknown UUID creates the entry
			if ip, _ := in["address"].(string); net.ParseIP(ip) == nil {
				reply(map[string]any{"result": "failed", "validations": map[string]any{"neighbor.address": "A value is required."}})
				return
			}
			n = map[string]string{"enabled": "1", "description": "", "address": "", "pollinterval": "", "priority": ""}
			f.nbrs[id] = n
		}
		f.store(n, in)
		reply(map[string]any{"result": "saved"})
	case strings.HasPrefix(p, "/api/quagga/ospfsettings/delNeighbor/"):
		id := strings.TrimPrefix(p, "/api/quagga/ospfsettings/delNeighbor/")
		if f.nbrs[id] == nil {
			reply(map[string]any{"result": "not found"})
			return
		}
		if !f.delKeeps {
			delete(f.nbrs, id)
		}
		if f.delSilent {
			return
		}
		reply(map[string]any{"result": "deleted"})
	case p == "/api/quagga/ospfsettings/searchNeighbor":
		var rows []map[string]string
		for id, n := range f.nbrs {
			row := map[string]string{"uuid": id}
			for k, v := range n {
				row[k] = v
			}
			rows = append(rows, row)
		}
		total := len(rows)
		for _, id := range f.virtualRows {
			rows = append(rows, map[string]string{"uuid": id})
		}
		all := r.URL.Query().Get("rowCount") == "-1"
		if v, ok := body["rowCount"]; ok && fmt.Sprint(v) == "-1" {
			all = true
		}
		if !all && f.searchPage > 0 && len(rows) > f.searchPage {
			rows = rows[:f.searchPage] // OPNsense pages when rowCount is not -1
		}
		reply(map[string]any{"rows": rows, "rowCount": len(rows), "total": total, "current": 1})
	case p == "/api/quagga/service/reconfigure":
		f.applied++
		if f.applyAnswer != nil {
			reply(f.applyAnswer)
			return
		}
		reply(map[string]any{"status": "ok"})
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"errorMessage":"Endpoint not found"}`)
	}
}

func (f *fakeFirewall) store(n map[string]string, in map[string]any) {
	for k, v := range in {
		if _, known := n[k]; known && !f.dropSets[k] {
			n[k] = fmt.Sprint(v)
			if f.encodeSets[k] {
				n[k] = base64.StdEncoding.EncodeToString([]byte(n[k]))
			}
		}
	}
}

// ospfObject renders the settings as OPNsense does, with the entry lists
// inside (which the settings resource must ignore).
func (f *fakeFirewall) ospfObject() map[string]any {
	o := map[string]any{"neighbors": map[string]any{"neighbor": []any{}}}
	for k, v := range f.ospf {
		o[k] = v
	}
	return o
}

// blankNeighbor: what getNeighbor answers without a UUID (a new entry with
// the model's defaults).
func blankNeighbor() map[string]any {
	return map[string]any{"enabled": "1", "description": "", "address": "", "pollinterval": "", "priority": ""}
}
