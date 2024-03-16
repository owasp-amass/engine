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

type securityTrails struct {
	Name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewSecurityTrails() et.Plugin {
	return &securityTrails{
		Name:   "SecurityTrails",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (st *securityTrails) Start(r et.Registry) error {
	st.log = r.Log().WithGroup("plugin").With("name", st.Name)

	name := "SecurityTrails-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   st.check,
	}); err != nil {
		st.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	st.log.Info("Plugin started")
	return nil
}

func (st *securityTrails) Stop() {
	st.log.Info("Plugin stopped")
}

func (st *securityTrails) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(st.Name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "securitytrails")
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

		st.rlimit.Take()
		r, err := st.query(domlt, cr.Apikey)
		if err == nil {
			body = r
			break
		}

		n := st.Name + "-Handler"
		st.log.Error(fmt.Sprintf("Failed to use the API endpoint: %v", err), "handler", n)
	}

	if body != "" {
		st.process(e, domlt, body)
	}
	return nil
}

func (st *securityTrails) query(domain, key string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL:    "https://api.securitytrails.com/v1/domain/" + domain + "/subdomains",
		Header: map[string]string{"APIKEY": key},
	})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (st *securityTrails) process(e *et.Event, domain, body string) {
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
			st.submitCallback(e, name)
		}
	}
}

func (st *securityTrails) submitCallback(e *et.Event, name string) {
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
