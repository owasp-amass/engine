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

	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type passiveTotal struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewPassiveTotal() et.Plugin {
	return &passiveTotal{
		name:   "PassiveTotal",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
	}
}

func (pt *passiveTotal) Name() string {
	return pt.name
}

func (pt *passiveTotal) Start(r et.Registry) error {
	pt.log = r.Log().WithGroup("plugin").With("name", pt.name)

	name := pt.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     pt,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   pt.check,
	}); err != nil {
		return err
	}

	pt.log.Info("Plugin started")
	return nil
}

func (pt *passiveTotal) Stop() {
	pt.log.Info("Plugin stopped")
}

func (pt *passiveTotal) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(pt.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	names := support.NewFQDNFilter()
	defer names.Close()

	for _, cr := range ds.Creds {
		if cr == nil || cr.Username == "" || cr.Apikey == "" {
			continue
		}

		var lastid string
		body, err := pt.query(domlt, "", cr.Username, cr.Apikey)
		if err == nil {
			lastid = pt.process(e, domlt, body, names)

			for lastid != "" {
				id := lastid
				lastid = ""

				body, err = pt.query(domlt, id, cr.Username, cr.Apikey)
				if err == nil {
					lastid = pt.process(e, domlt, body, names)
				}
			}
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", pt.name, "handler", pt.name+"-Handler"))
	}

	names.Prune(1000)
	for _, name := range names.Slice() {
		support.SubmitFQDNGuess(e, name)
	}
	return nil
}

func (pt *passiveTotal) query(domain, lastid, username, key string) (string, error) {
	pt.rlimit.Take()

	url := "https://api.riskiq.net/pt/v2/enrichment/subdomains?query=" + domain
	if lastid != "" {
		url += "&lastId=" + lastid
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: url,
		Auth: &http.BasicAuth{
			Username: username,
			Password: key,
		},
	})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (pt *passiveTotal) process(e *et.Event, domain, body string, names support.FQDNFilter) string {
	var result struct {
		Success    bool     `json:"success"`
		Subdomains []string `json:"subdomains"`
		LastID     string   `json:"lastId"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil || !result.Success {
		return ""
	}

	for _, sub := range result.Subdomains {
		fqdn := http.CleanName(sub + "." + domain)
		// if the subdomain is not in scope, skip it
		if fqdn != "" && e.Session.Config().IsDomainInScope(fqdn) {
			names.Insert(fqdn)
		}
	}
	return result.LastID
}
