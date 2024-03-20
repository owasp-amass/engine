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
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/engine/net/dns"
	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type zetalytics struct {
	Name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewZetalytics() et.Plugin {
	return &zetalytics{
		Name:   "ZETAlytics",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
	}
}

func (z *zetalytics) Start(r et.Registry) error {
	z.log = r.Log().WithGroup("plugin").With("name", z.Name)

	name := z.Name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   z.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", z.Name, "handler", name))
		return err
	}

	z.log.Info("Plugin started")
	return nil
}

func (z *zetalytics) Stop() {
	z.log.Info("Plugin stopped")
}

func (z *zetalytics) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(z.Name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "zetalytics")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	names := support.NewFQDNFilter()
	defer names.Close()

	for _, cr := range ds.Creds {
		if cr == nil || cr.Apikey == "" {
			continue
		}

		z.rlimit.Take()
		if body, err := z.query(domlt, cr.Apikey); err == nil && body != "" {
			z.process(e, body, names)
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", z.Name, "handler", z.Name+"-Handler"))
	}

	names.Prune(1000)
	for _, name := range names.Slice() {
		support.SubmitFQDNGuess(e, name)
	}
	return nil
}

func (z *zetalytics) query(domain, key string) (string, error) {
	start := time.Now().Add((time.Hour * 24) * -90).Unix() // The epoch 90 days ago
	url := "https://zonecruncher.com/api/v1/subdomains?q=" + domain +
		"&token=" + key + "&tsfield=last_seen&start=" + strconv.FormatInt(start, 10)

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: url})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (z *zetalytics) process(e *et.Event, body string, names support.FQDNFilter) {
	var result struct {
		Total      int `json:"total"`
		Subdomains []struct {
			FQDN string `json:"qname"`
			//FirstSeen string `json:"first_seen"`
			//LastSeen  string `json:"last_seen"`
		} `json:"results"`
		Msg string `json:"msg"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil || result.Total == 0 {
		return
	}

	for _, s := range result.Subdomains {
		fqdn := dns.RemoveAsteriskLabel(http.CleanName(s.FQDN))
		// if the subdomain is not in scope, skip it
		if fqdn != "" && e.Session.Config().IsDomainInScope(fqdn) {
			names.Insert(fqdn)
		}
	}
}
