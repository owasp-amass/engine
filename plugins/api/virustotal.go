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

type virusTotal struct {
	Name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewVirusTotal() et.Plugin {
	return &virusTotal{
		Name:   "VirusTotal",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
	}
}

func (vt *virusTotal) Start(r et.Registry) error {
	vt.log = r.Log().WithGroup("plugin").With("name", vt.Name)

	name := "VirusTotal-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   vt.check,
	}); err != nil {
		vt.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	vt.log.Info("Plugin started")
	return nil
}

func (vt *virusTotal) Stop() {
	vt.log.Info("Plugin stopped")
}

func (vt *virusTotal) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(vt.Name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "virustotal")
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

		vt.rlimit.Take()
		r, err := vt.query(domlt, cr.Apikey)
		if err == nil {
			body = r
			break
		}

		n := vt.Name + "-Handler"
		vt.log.Error(fmt.Sprintf("Failed to use the API endpoint: %v", err), "handler", n)
	}

	if body != "" {
		vt.process(e, body)
	}
	return nil
}

func (vt *virusTotal) query(domain, key string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + domain + "&apikey=" + key,
	})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (vt *virusTotal) process(e *et.Event, body string) {
	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return
	}

	for _, sub := range result.Subdomains {
		fqdn := dns.RemoveAsteriskLabel(sub)
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(fqdn))
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			vt.submitCallback(e, name)
		}
	}
}

func (vt *virusTotal) submitCallback(e *et.Event, name string) {
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
