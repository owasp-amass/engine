// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
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

type duckDuckGo struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewDuckDuckGo() et.Plugin {
	return &duckDuckGo{
		name:   "DuckDuckGo",
		fmtstr: "https://html.duckduckgo.com/html/?q=site:%s -site:www.%s",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (d *duckDuckGo) Name() string {
	return d.name
}

func (d *duckDuckGo) Start(r et.Registry) error {
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

func (d *duckDuckGo) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *duckDuckGo) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	d.rlimit.Take()
	if body, err := d.query(domlt); err == nil {
		d.process(e, body)
	}
	return nil
}

func (d *duckDuckGo) query(name string) (string, error) {
	req := &http.Request{URL: fmt.Sprintf(d.fmtstr, name, name)}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", err
	}

	return resp.Body, nil
}

func (d *duckDuckGo) process(e *et.Event, body string) {
	for _, name := range support.ScrapeSubdomainNames(body) {
		n := strings.ToLower(strings.TrimSpace(name))
		// if the subdomain is not in scope, skip it
		if n != "" && e.Session.Config().IsDomainInScope(n) {
			d.submitCallback(e, n)
		}
	}
}

func (d *duckDuckGo) submitCallback(e *et.Event, name string) {
	support.AppendToDBQueue(func() {
		if a, err := e.Session.DB().Create(nil, "",
			&domain.FQDN{Name: name}); err == nil && a != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    name,
				Asset:   a,
				Session: e.Session,
			})
		}
	})
}
