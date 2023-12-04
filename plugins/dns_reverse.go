// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

const (
	defaultSweepSize = 250
	activeSweepSize  = 500
	maxSweepSize     = 1000
)

type dnsReverse struct{}

func newDNSReverse() Plugin {
	return &dnsReverse{}
}

func (d *dnsReverse) Start(r *registry.Registry) error {
	name := "DNS-Reverse-Handler"

	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Priority:   9,
		Transforms: []string{"fqdn"},
		EventType:  oam.IPAddress,
		Handler:    d.handler,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (d *dnsReverse) Stop() {}

func (d *dnsReverse) handler(e *et.Event) error {
	session := e.Session.(*sessions.Session)

	data, ok := e.Data.(*et.AssetData)
	if !ok {
		return errors.New("failed to extract the event data")
	}

	ip, ok := data.OAMAsset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	matches, err := checkTransformations(session, "ipaddress", "fqdn", "dns")
	if err != nil {
		return err
	}
	if _, ok := matches["fqdn"]; !ok {
		return nil
	}

	// check that the IP address is related to a FQDN that is in scope
	if addr, hit := session.Cache.GetAsset(ip); hit && addr != nil {
		rtype := "a_record"
		if ip.Type == "IPv6" {
			rtype = "aaaa_record"
		}

		var inscope bool
		if relations, hit := session.Cache.GetRelations(&dbt.Relation{
			Type:    rtype,
			ToAsset: addr,
		}); hit && len(relations) > 0 {
			for _, relation := range relations {
				a := relation.FromAsset.Asset

				if fqdn, ok := a.(*domain.FQDN); ok && session.Cfg.IsDomainInScope(fqdn.Name) {
					inscope = true
					break
				}
			}
		}

		if inscope {
			d.sweep(e, ip)
		}
	}

	return nil
}

func (d dnsReverse) sweep(e *et.Event, address *oamnet.IPAddress) {
	session := e.Session.(*sessions.Session)

	n, err := ipToNetblockWithAttempts(session, address, 10, 500*time.Millisecond)
	if err != nil {
		return
	}

	addrstr := address.Address.String()
	_, cidr, err := net.ParseCIDR(n.Cidr.String())
	if err != nil || cidr == nil {
		addr := net.ParseIP(addrstr)
		mask := net.CIDRMask(18, 32)
		if amassnet.IsIPv6(addr) {
			mask = net.CIDRMask(64, 128)
		}

		cidr = &net.IPNet{
			IP:   addr.Mask(mask),
			Mask: mask,
		}
	}

	size := defaultSweepSize
	if session.Cfg.Active {
		size = activeSweepSize
	}

	for _, ip := range amassnet.CIDRSubset(cidr, addrstr, size) {
		a := &network.IPAddress{Address: netip.MustParseAddr(ip.String())}
		if _, hit := session.Cache.GetAsset(a); hit && ip.String() != addrstr {
			continue
		}

		if rr, err := performQuery(ip.String(), dns.TypePTR); err == nil && len(rr) > 0 {
			d.processRecords(e, rr)
		}
	}
}

func (d *dnsReverse) processRecords(e *et.Event, rr []*resolve.ExtractedAnswer) {
	session := e.Session.(*sessions.Session)
	g := graph.Graph{DB: session.DB}

	for _, record := range rr {
		go func(event *et.Event, r *resolve.ExtractedAnswer) {
			if !session.Cfg.IsDomainInScope(r.Data) {
				return
			}
			if a, err := g.UpsertPTR(context.TODO(), r.Name, r.Data); err == nil && a != nil {
				scheduleAssetEvent(event, r.Data, a)
			}
		}(e, record)
	}
}
