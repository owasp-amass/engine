// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type hackerTarget struct {
	URL string
}

func newHackerTarget() Plugin {
	return &hackerTarget{
		URL: "https://api.hackertarget.com/hostsearch/?q=",
	}
}

func (ht *hackerTarget) Start(r *registry.Registry) error {
	name := "HackerTarget-Subdomain-Handler"
	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Handler:    ht.lookup,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (ht *hackerTarget) Stop() {}

// lookup function queries the HackerTarget API for subdomains related to a root domain.
func (ht *hackerTarget) lookup(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	session := e.Session.(*sessions.Session)
	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if session.Cfg.WhichDomain(domlt) != domlt {
		return nil
	}

	matches, err := checkTransformations(session, "fqdn", "fqdn", "hackertarget")
	if err != nil {
		return err
	}
	if _, found := matches["fqdn"]; !found {
		return nil
	}

	records, err := ht.query(domlt)
	if err != nil {
		return err
	}

	ht.process(e, records)
	return nil
}

func (ht *hackerTarget) query(name string) ([][]string, error) {
	resp, err := http.Get(ht.URL + name)
	if err != nil {
		return nil, fmt.Errorf("error fetching URL: %w", err)
	}
	defer resp.Body.Close()

	return csv.NewReader(resp.Body).ReadAll()
}

func (ht *hackerTarget) process(e *et.Event, records [][]string) {
	session := e.Session.(*sessions.Session)
	d := e.Dispatcher.(*dispatcher.Dispatcher)

	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(record[0]))
		if name != "" && session.Cfg.IsDomainInScope(name) {
			if a, err := session.DB.Create(nil, "", &domain.FQDN{Name: name}); err == nil && a != nil {
				_ = d.DispatchEvent(&et.Event{
					Name:       name,
					Asset:      a,
					Dispatcher: d,
					Session:    session,
				})
			}
		}
	}
}
