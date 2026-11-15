// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package opnsense is a client for the OPNsense API that adapts to the
// firewall it talks to: it detects the core version and the installed
// plugins, picks the matching capability data, and refuses to send
// resources, fields or values that version does not have (OPNsense would
// silently ignore them). After every write it reads the object back.
//
//	c, err := opnsense.New(ctx, opnsense.Config{URL: "https://fw.example", Key: k, Secret: s})
//	hosts, err := c.Entries("unbound/settings#hosts.host")
//	id, err := hosts.Add(ctx, opnsense.Values{"hostname": "nas", "domain": "example.com", "server": "192.0.2.10"})
//	err = c.Apply(ctx)
package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Values maps field paths ("hostname", "general.enabled") to values: bool,
// int64 (or another integer type), string, or []string for list fields.
// Read values use exactly these types; bool and int fields that are empty
// on the firewall are nil.
type Values map[string]any

// Policy for combinations of core and plugin versions the capability data
// has not seen.
type Policy = capability.Policy

const (
	// AssumeNewestInSeries uses the nearest data of the same series and
	// reports a warning in Instance().Warnings. Read-back still catches
	// a field that does not behave as the data says.
	AssumeNewestInSeries = capability.AssumeNewestInSeries
	// Refuse fails New when any installed package is not an exact match.
	Refuse = capability.Refuse
)

// TLS settings. Verification is always on; there is no switch to turn it
// off. Without CAFile, CAPEM or PinSHA256 the system roots are used.
type TLS struct {
	CAFile    string // PEM file with the CA that signed the firewall's certificate
	CAPEM     []byte // the same as bytes
	PinSHA256 string // SHA-256 of the firewall's certificate (hex, colons allowed); for self-signed certificates
}

// Config of a client.
type Config struct {
	URL    string // https://host[:port]
	Key    string
	Secret string
	TLS    TLS

	// UnknownVersion decides what happens with versions the data has not
	// seen. Default: AssumeNewestInSeries.
	UnknownVersion Policy
	// Capabilities is the data to use. If nil, CapabilityDir is loaded.
	// (Embedded data follows in a later release.)
	Capabilities *capability.Set
	// CapabilityDir is an unpacked "catalog" release: catalog.json and
	// capabilities/<package>.json.
	CapabilityDir string

	// AutoApply applies after every successful mutation.
	AutoApply bool

	Timeout      time.Duration // per request, default 60s
	ApplyTimeout time.Duration // apply endpoints, default 5m
	Logger       *slog.Logger  // debug log: method, path, status, duration
	HTTPClient   *http.Client  // replaces the built-in HTTP client (tests)
}

// Instance describes the detected firewall.
type Instance struct {
	Core     string            // core version as reported, e.g. 26.7.9_1
	Plugins  map[string]string // installed plugin -> version
	Resolved *capability.Resolved
	Warnings []string
}

// Client talks to one firewall.
type Client struct {
	cfg  Config
	t    *transport.Transport
	data *capability.Set
	inst *Instance
	owns map[string][]string // resource -> packages that define it

	mu      sync.Mutex
	pending map[string]bool        // apply endpoints
	locks   map[string]*sync.Mutex // per model class
}

// New connects, detects the firewall and resolves the capability data.
func New(ctx context.Context, cfg Config) (*Client, error) {
	data := cfg.Capabilities
	if data == nil {
		if cfg.CapabilityDir == "" {
			return nil, errors.New("opnsense: no capability data (Config.Capabilities or Config.CapabilityDir)")
		}
		var err error
		data, err = capability.Load(os.DirFS(cfg.CapabilityDir))
		if err != nil {
			return nil, fmt.Errorf("opnsense: capability data: %w", err)
		}
	}
	tc := transport.Config{URL: cfg.URL, Key: cfg.Key, Secret: cfg.Secret, Pin: cfg.TLS.PinSHA256,
		CAPEM: cfg.TLS.CAPEM, Timeout: cfg.Timeout, Logger: cfg.Logger, HTTP: cfg.HTTPClient}
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("opnsense: CA file: %w", err)
		}
		tc.CAPEM = append(append([]byte{}, tc.CAPEM...), pem...)
	}
	t, err := transport.New(tc)
	if err != nil {
		return nil, err
	}
	if cfg.ApplyTimeout == 0 {
		cfg.ApplyTimeout = 5 * time.Minute
	}
	c := &Client{cfg: cfg, t: t, data: data, owns: map[string][]string{},
		pending: map[string]bool{}, locks: map[string]*sync.Mutex{}}
	for pkg, d := range data.Docs {
		for id := range d.Resources {
			c.owns[id] = append(c.owns[id], pkg)
		}
	}
	for id := range c.owns {
		sort.Strings(c.owns[id])
	}
	if err := c.detect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Instance returns what was detected; Warnings lists every assumption.
func (c *Client) Instance() *Instance { return c.inst }

// Data returns the capability data in use.
func (c *Client) Data() *capability.Set { return c.data }

type pkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed string `json:"installed"`
}

func (c *Client) detect(ctx context.Context) error {
	var info struct {
		ProductVersion string    `json:"product_version"`
		ProductID      string    `json:"product_id"`
		Package        []pkgInfo `json:"package"`
		Plugin         []pkgInfo `json:"plugin"`
	}
	inst := &Instance{Plugins: map[string]string{}}
	err := c.t.Get(ctx, "/api/core/firmware/info", &info)
	if errors.Is(err, ErrUnauthorized) {
		return err
	}
	if err == nil {
		inst.Core = info.ProductVersion
		for _, p := range info.Package {
			if p.Name == info.ProductID && p.Installed == "1" && p.Version != "" {
				inst.Core = p.Version
			}
			if strings.HasPrefix(p.Name, "os-") && p.Installed == "1" {
				inst.Plugins[p.Name] = p.Version
			}
		}
		for _, p := range info.Plugin {
			if p.Installed == "1" {
				inst.Plugins[p.Name] = p.Version
			}
		}
	} else {
		// fall back to the core version alone
		var st struct {
			ProductVersion string `json:"product_version"`
			Product        struct {
				ProductVersion string `json:"product_version"`
			} `json:"product"`
		}
		if err2 := c.t.Get(ctx, "/api/core/firmware/status", &st); err2 != nil {
			return fmt.Errorf("opnsense: detecting the firmware: %w", errors.Join(err, err2))
		}
		inst.Core = st.ProductVersion
		if inst.Core == "" {
			inst.Core = st.Product.ProductVersion
		}
		inst.Warnings = append(inst.Warnings, "plugin list not available ("+err.Error()+"); only the core is used")
	}
	if inst.Core == "" {
		return errors.New("opnsense: the firewall did not report its version")
	}
	res, err := c.data.Resolve(inst.Core, inst.Plugins, c.cfg.UnknownVersion)
	if err != nil {
		return fmt.Errorf("opnsense: %w", err)
	}
	inst.Resolved = res
	inst.Warnings = append(inst.Warnings, res.Warnings...)
	c.inst = inst
	return nil
}

// bound is a resource resolved for this firewall.
type bound struct {
	c        *Client
	id       string
	pkg      string
	version  string
	frag     string
	res      *capability.Resource
	api      *capability.API
	verified *capability.ResVerify
}

func (c *Client) bind(id, kind string) (*bound, error) {
	pkgs := c.owns[id]
	if len(pkgs) == 0 {
		return nil, &ErrNotAvailable{Resource: id}
	}
	var first *ErrNotAvailable
	for _, pkg := range pkgs {
		r := c.data.Docs[pkg].Resources[id]
		res := c.inst.Resolved.Packages[pkg]
		if res != nil && res.Fragment != "" && r.Available(res.Fragment) {
			if r.Kind != kind {
				return nil, fmt.Errorf("opnsense: %s is a %s resource, not %s", id, r.Kind, kind)
			}
			return &bound{c: c, id: id, pkg: pkg, version: res.Version, frag: res.Fragment, res: r,
				api: r.APIFor(res.Fragment), verified: r.Verified[res.Fragment]}, nil
		}
		if first == nil {
			e := &ErrNotAvailable{Resource: id, Package: pkg, AvailableIn: c.versions(pkg, r.In)}
			if res != nil {
				e.Have = res.Version
			}
			first = e
		}
	}
	return nil, first
}

// versions lists the package versions of the given fragments.
func (c *Client) versions(pkg string, frags []string) []string {
	d := c.data.Docs[pkg]
	seen := map[string]bool{}
	var out []string
	for _, h := range frags {
		for _, v := range d.Fragments[h].Versions {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return capability.CompareVersions(out[i], out[j]) < 0 })
	return out
}

func (c *Client) lock(model string) func() {
	c.mu.Lock()
	m := c.locks[model]
	if m == nil {
		m = &sync.Mutex{}
		c.locks[model] = m
	}
	c.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func (c *Client) markPending(apply string) {
	if apply == "" {
		return
	}
	c.mu.Lock()
	c.pending[apply] = true
	c.mu.Unlock()
}

// Pending lists the apply endpoints that Apply would call.
func (c *Client) Pending() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.pending))
	for p := range c.pending {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Apply activates saved changes: every pending apply endpoint is called
// once. Writes alone change only the stored configuration.
func (c *Client) Apply(ctx context.Context) error {
	var errs []error
	for _, p := range c.Pending() {
		var resp map[string]any
		err := c.t.Post(ctx, p, nil, &resp, c.cfg.ApplyTimeout)
		if err == nil {
			if st, _ := resp["status"].(string); strings.EqualFold(st, "failed") || strings.EqualFold(st, "error") {
				err = fmt.Errorf("opnsense: apply %s: status %q", p, st)
			}
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		c.mu.Lock()
		delete(c.pending, p)
		c.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (c *Client) afterMutation(ctx context.Context, apply string) error {
	c.markPending(apply)
	if c.cfg.AutoApply {
		return c.Apply(ctx)
	}
	return nil
}
