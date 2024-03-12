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

type rapidDNS struct {
	Name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewRapidDNS() et.Plugin {
	return &rapidDNS{
		Name:   "RapidDNS",
		fmtstr: "https://rapiddns.io/subdomain/%s?full=1",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
	}
}

func (rd *rapidDNS) Start(r et.Registry) error {
	rd.log = r.Log().WithGroup("plugin").With("name", rd.Name)

	name := "RapidDNS-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   rd.check,
	}); err != nil {
		rd.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	rd.log.Info("Plugin started")
	return nil
}

func (rd *rapidDNS) Stop() {
	rd.log.Info("Plugin stopped")
}

func (rd *rapidDNS) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "rapiddns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	rd.rlimit.Take()
	body, err := rd.query(domlt)
	if err != nil {
		return err
	}

	rd.process(e, body)
	return nil
}

func (rd *rapidDNS) query(name string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(rd.fmtstr, name)})
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %w", err)
	}

	return resp.Body, nil
}

func (rd *rapidDNS) process(e *et.Event, body string) {
	for _, name := range support.ScrapeSubdomainNames(body) {
		n := strings.ToLower(strings.TrimSpace(name))
		// if the subdomain is not in scope, skip it
		if n != "" && e.Session.Config().IsDomainInScope(n) {
			rd.submitCallback(e, n)
		}
	}
}

func (rd *rapidDNS) submitCallback(e *et.Event, name string) {
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
