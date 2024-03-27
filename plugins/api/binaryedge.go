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

	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type binaryEdge struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewBinaryEdge() et.Plugin {
	return &binaryEdge{
		name:   "BinaryEdge",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
	}
}

func (be *binaryEdge) Name() string {
	return be.name
}

func (be *binaryEdge) Start(r et.Registry) error {
	be.log = r.Log().WithGroup("plugin").With("name", be.name)

	name := be.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     be,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   be.check,
	}); err != nil {
		return err
	}

	be.log.Info("Plugin started")
	return nil
}

func (be *binaryEdge) Stop() {
	be.log.Info("Plugin stopped")
}

func (be *binaryEdge) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(be.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	var success bool
loop:
	for i := 1; i <= 500; i++ {
		for _, cr := range ds.Creds {
			if cr == nil || cr.Apikey == "" {
				continue
			}

			be.rlimit.Take()
			body, err := be.query(domlt, cr.Apikey, strconv.Itoa(i))
			if err == nil && body != "" {
				success = true
				if !be.process(e, body) {
					break loop
				}
				break
			}
		}
	}

	if !success {
		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint for domain: %s", domlt),
			slog.Group("plugin", "name", be.name, "handler", be.name+"-Handler"))
	}
	return nil
}

func (be *binaryEdge) query(domain, key, pagenum string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		Header: map[string]string{"X-KEY": key},
		URL:    "https://api.binaryedge.io/v2/query/domains/subdomain/" + domain + "?page=" + pagenum,
	})

	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (be *binaryEdge) process(e *et.Event, body string) bool {
	var resp struct {
		Results struct {
			Page     int      `json:"page"`
			PageSize int      `json:"pagesize"`
			Total    int      `json:"total"`
			Events   []string `json:"events"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte("{\"results\":"+body+"}"), &resp); err != nil {
		return false
	}

	for _, name := range resp.Results.Events {
		// if the subdomain is not in scope, skip it
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			support.SubmitFQDNGuess(e, name)
		}
	}

	var cont bool
	if resp.Results.Page > 0 && resp.Results.Page <= 500 && resp.Results.PageSize > 0 &&
		resp.Results.Total > 0 && resp.Results.Page <= (resp.Results.Total/resp.Results.PageSize) {
		cont = true
	}
	return cont
}
