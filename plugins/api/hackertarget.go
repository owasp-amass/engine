// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/csv"
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

type hackerTarget struct {
	Name   string
	URL    string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewHackerTarget() et.Plugin {
	return &hackerTarget{
		Name:   "HackerTarget",
		URL:    "https://api.hackertarget.com/hostsearch/?q=",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (ht *hackerTarget) Start(r et.Registry) error {
	ht.log = r.Log().WithGroup("plugin").With("name", ht.Name)

	name := "HackerTarget-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   ht.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", ht.Name, "handler", name))
		return err
	}

	ht.log.Info("Plugin started")
	return nil
}

func (ht *hackerTarget) Stop() {
	ht.log.Info("Plugin stopped")
}

func (ht *hackerTarget) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "hackertarget")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	ht.rlimit.Take()
	records, err := ht.query(domlt)
	if err != nil {
		return err
	}

	ht.process(e, records)
	return nil
}

func (ht *hackerTarget) query(name string) ([][]string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: ht.URL + name})
	if err != nil {
		return nil, err
	}

	return csv.NewReader(strings.NewReader(resp.Body)).ReadAll()
}

func (ht *hackerTarget) process(e *et.Event, records [][]string) {
	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(record[0]))
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			ht.submitCallback(e, name)
		}
	}
}

func (ht *hackerTarget) submitCallback(e *et.Event, name string) {
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
