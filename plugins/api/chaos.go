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

	"github.com/owasp-amass/engine/net/dns"
	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type chaos struct {
	Name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewChaos() et.Plugin {
	return &chaos{
		Name:   "Chaos",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
	}
}

func (c *chaos) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.Name)

	name := "Chaos-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   c.check,
	}); err != nil {
		c.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *chaos) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *chaos) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(c.Name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "chaos")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	var body string
	for _, cr := range ds.Creds {
		if cr == nil || cr.Apikey == "" {
			continue
		}

		c.rlimit.Take()
		if r, err := c.query(domlt, cr.Apikey); err == nil {
			body = r
			break
		}
	}

	if body != "" {
		c.process(e, domlt, body)
	}
	return nil
}

func (c *chaos) query(domain, key string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL:    "https://dns.projectdiscovery.io/dns/" + domain + "/subdomains",
		Header: map[string]string{"Authorization": key},
	})
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %w", err)
	}
	return resp.Body, nil
}

func (c *chaos) process(e *et.Event, domain, body string) {
	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return
	}

	for _, sub := range result.Subdomains {
		fqdn := dns.RemoveAsteriskLabel(sub + "." + domain)
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(fqdn))
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			c.submitCallback(e, name)
		}
	}
}

func (c *chaos) submitCallback(e *et.Event, name string) {
	support.AppendToDBQueue(func() {
		if a, err := e.Session.DB().Create(nil, "", &domain.FQDN{Name: name}); err == nil && a != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    name,
				Asset:   a,
				Session: e.Session,
			})
		}
	})
}
