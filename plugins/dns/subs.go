// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

type subsQtypes struct {
	Qtype uint16
	Rtype string
}

type dnsSubs struct {
	types []subsQtypes
	queue queue.Queue
	done  chan struct{}
}

func NewSubs() et.Plugin {
	return &dnsSubs{
		types: []subsQtypes{
			{Qtype: dns.TypeNS, Rtype: "ns_record"},
			{Qtype: dns.TypeMX, Rtype: "mx_record"},
			//{Qtype: dns.TypeSOA, Rtype: "soa_record"},
			//{Qtype: dns.TypeSPF, Rtype: "spf_record"},
		},
		queue: queue.NewQueue(),
		done:  make(chan struct{}),
	}
}

func (d *dnsSubs) Start(r et.Registry) error {
	name := "DNS-Subdomains-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     3,
		MaxInstances: support.NumTrustedResolvers(),
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		r.Log().Printf("Failed to register the %s: %v", name, err)
		return err
	}

	go d.process()
	return nil
}

func (d *dnsSubs) Stop() {
	close(d.done)
}

func (d *dnsSubs) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}

	if matches.IsMatch("fqdn") && support.NameResolved(e.Session, fqdn) {
		d.traverse(e, fqdn)
	}
	return nil
}

func (d *dnsSubs) traverse(e *et.Event, n *domain.FQDN) {
	sub := n.Name
	var wg sync.WaitGroup

	dom := d.registered(e, sub)
	if dom == "" {
		return
	}
	if sub == dom {
		d.queries(e, sub, &wg)
		wg.Wait()
		return
	}
	dlabels := strings.Split(dom, ".")

	for {
		labels := strings.Split(sub, ".")
		// Is this large enough to consider further?
		if len(labels) < 2 {
			break
		}
		sub = strings.TrimSpace(strings.Join(labels[1:], "."))
		// no need to check subdomains already evaluated
		if _, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: sub}); hit {
			break
		}
		if len(dlabels) > len(labels) {
			break
		}
		d.queries(e, sub, &wg)
	}
	wg.Wait()
}

func (d *dnsSubs) queries(e *et.Event, subdomain string, wg *sync.WaitGroup) {
	for i, t := range d.types {
		if rr, err := support.PerformQuery(subdomain, t.Qtype); err == nil && len(rr) > 0 {
			wg.Add(1)
			d.callbackClosure(e, t.Rtype, rr, wg)
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			break
		}
	}
}

func (d *dnsSubs) callbackClosure(e *et.Event, rtype string, rr []*resolve.ExtractedAnswer, wg *sync.WaitGroup) {
	g := graph.Graph{DB: e.Session.DB()}

	d.queue.Append(func() {
		defer wg.Done()

		for _, record := range rr {
			fqdn, err := g.UpsertFQDN(context.TODO(), record.Name)
			if err != nil || fqdn == nil {
				continue
			}

			a, err := e.Session.DB().Create(fqdn, rtype, &domain.FQDN{Name: record.Data})
			if err != nil || a == nil {
				continue
			}

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    record.Data,
				Asset:   a,
				Session: e.Session,
			})

			if from, hit := e.Session.Cache().GetAsset(fqdn.Asset); hit && from != nil {
				if to, hit := e.Session.Cache().GetAsset(a.Asset); hit && to != nil {
					now := time.Now()

					e.Session.Cache().SetRelation(&dbt.Relation{
						Type:      rtype,
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: fqdn,
						ToAsset:   to,
					})
				}
			}
		}
	})
}

func (d *dnsSubs) process() {
	for {
		select {
		case <-d.done:
			return
		case <-d.queue.Signal():
			d.queue.Process(func(data interface{}) {
				if callback, ok := data.(func()); ok {
					callback()
				}
			})
		}
	}
}

func (d *dnsSubs) registered(e *et.Event, name string) string {
	if dom := e.Session.Config().WhichDomain(name); dom != "" {
		return dom
	}

	fqdn, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name})
	if !hit || fqdn == nil {
		return ""
	}

	now := time.Now()
	var rels []*dbt.Relation
	for _, rtype := range []string{"ns_record", "mx_record"} {
		if r, hit := e.Session.Cache().GetRelations(&dbt.Relation{
			Type:      rtype,
			CreatedAt: now,
			LastSeen:  now,
			ToAsset:   fqdn,
		}); hit && len(r) > 0 {
			rels = append(rels, r...)
		}
	}

	var found bool
	for _, r := range rels {
		if from, ok := r.FromAsset.Asset.(*domain.FQDN); ok &&
			from != nil && e.Session.Config().IsDomainInScope(from.Name) {
			found = true
			break
		}
	}
	if found {
		if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			return dom
		}
	}
	return ""
}
