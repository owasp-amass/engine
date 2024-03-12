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

type bing struct {
	Name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewBing() et.Plugin {
	return &bing{
		Name:   "Bing",
		fmtstr: "https://www.ask.com/web?o=0&l=dir&qo=pagination&page=%d&q=site:%s -www.%s",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (b *bing) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.Name)

	name := "Bing-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   b.check,
	}); err != nil {
		b.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bing) Stop() {
	b.log.Info("Plugin stopped")
}

func (b *bing) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "ask")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	for i := 1; i < 10; i++ {
		b.rlimit.Take()
		if body, err := b.query(domlt, i); err == nil {
			b.process(e, body)
		}
	}
	return nil
}

func (b *bing) query(name string, itemnum int) (string, error) {
	req := &http.Request{URL: fmt.Sprintf(b.fmtstr, itemnum, name, name)}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %w", err)
	}

	return resp.Body, nil
}

func (b *bing) process(e *et.Event, body string) {
	for _, name := range support.ScrapeSubdomainNames(body) {
		n := strings.ToLower(strings.TrimSpace(name))
		// if the subdomain is not in scope, skip it
		if n != "" && e.Session.Config().IsDomainInScope(n) {
			b.submitCallback(e, n)
		}
	}
}

func (b *bing) submitCallback(e *et.Event, name string) {
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
