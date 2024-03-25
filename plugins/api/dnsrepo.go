// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type dnsrepo struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewDNSRepo() et.Plugin {
	return &dnsrepo{
		name:   "DNSRepo",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
	}
}

func (d *dnsrepo) Name() string {
	return d.name
}

func (d *dnsrepo) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     d,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsrepo) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *dnsrepo) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	var keys []string
	ds := e.Session.Config().GetDataSourceConfig(d.name)
	if ds != nil {
		for _, cred := range ds.Creds {
			keys = append(keys, cred.Apikey)
		}
	}
	// add an empty API key
	keys = append(keys, "")

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	for _, key := range keys {
		d.rlimit.Take()

		body, err := d.query(domlt, key)
		if err == nil {
			if key == "" {
				d.processHTML(e, body)
			} else {
				d.processJSON(e, body)
			}
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	}

	return nil
}

func (d *dnsrepo) query(domain, key string) (string, error) {
	var req *http.Request

	if key == "" {
		req = &http.Request{URL: "https://dnsrepo.noc.org/?domain=" + domain}
	} else {
		req = &http.Request{
			URL: "https://dnsrepo.noc.org/api/?apikey=" + key + "&search=" + domain + "&limit=5000",
		}
	}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (d *dnsrepo) processHTML(e *et.Event, body string) {
	for _, sub := range support.ScrapeSubdomainNames(body) {
		if sub != "" {
			name := http.CleanName(sub)
			// if the subdomain is not in scope, skip it
			if name != "" && e.Session.Config().IsDomainInScope(name) {
				support.SubmitFQDNGuess(e, name)
			}
		}
	}
}

func (d *dnsrepo) processJSON(e *et.Event, body string) {
	var resp struct {
		Results []struct {
			Domain string   `json:"domain"`
			Alias  string   `json:"cname"`
			IPv4   []string `json:"ipv4"`
			IPv6   []string `json:"ipv6"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte("{\"results\":"+body+"}"), &resp); err != nil {
		return
	}

	set := stringset.New()
	defer set.Close()

	for _, r := range resp.Results {
		for _, sub := range []string{r.Domain, r.Alias} {
			if slen := len(sub); slen > 0 {
				name := sub
				// remove an ending dot from the name
				if sub[slen-1] == '.' {
					name = sub[:slen-1]
				}
				// if the subdomain is not in scope, skip it
				if name != "" && e.Session.Config().IsDomainInScope(name) {
					set.Insert(name)
				}
			}
		}
	}

	for _, fqdn := range set.Slice() {
		support.SubmitFQDNGuess(e, fqdn)
	}
}
