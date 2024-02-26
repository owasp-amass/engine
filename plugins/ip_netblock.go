// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type ipNetblock struct {
	Name string
	log  *slog.Logger
}

func newIPNetblock() et.Plugin {
	return &ipNetblock{Name: "IP-Netblock"}
}

func (d *ipNetblock) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.Name)

	name := "IP-Netblock-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Priority:   4,
		Transforms: []string{"netblock"},
		EventType:  oam.IPAddress,
		Callback:   d.lookup,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *ipNetblock) Stop() {
	d.log.Info("Plugin stopped")
}

// ipLookup function queries the bgptools whois server using an
// IP address to retrieve related ASN, netblock, and RIR details.
func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	matches, err := e.Session.Config().CheckTransformations("ipaddress", "netblock")
	if err != nil {
		return err
	}
	if !matches.IsMatch("netblock") {
		return nil
	}

	var netblock *oamnet.Netblock
	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		t := "IPv6"
		if prefix.Addr().Is4() {
			t = "IPv4"
		}

		netblock = &oamnet.Netblock{
			Cidr: prefix,
			Type: t,
		}

		d.reservedAS(e, netblock)
	} else {
		var err error

		netblock, err = support.IPToNetblockWithAttempts(e.Session, ip, 10, 500*time.Millisecond)
		if err != nil {
			return nil
		}
	}

	if nb, err := e.Session.DB().Create(nil, "", netblock); err == nil {
		if a, err := e.Session.DB().Create(nb, "contains", ip); err == nil {
			now := time.Now()

			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "contains",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: nb,
				ToAsset:   a,
			})

			if oamas, ok := a.Asset.(*oamnet.AutonomousSystem); ok {
				e.Session.Log().Info("relationship discovered", "from",
					netblock.Cidr.String(), "relation", "contains", "to", oamas.Number,
					slog.Group("plugin", "name", d.Name, "handler", "IP-Netblock-Handler"))
			}
		}
	}
	return nil
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	now := time.Now()
	g := graph.Graph{DB: e.Session.DB()}
	group := slog.Group("plugin", "name", d.Name, "handler", "IP-Netblock-Handler")

	asn, rir, err := g.UpsertAS(context.TODO(), 0, "Reserved Network Address Blocks")
	if err != nil || asn == nil || rir == nil {
		return
	}

	e.Session.Cache().SetAsset(asn)
	e.Session.Cache().SetAsset(rir)
	e.Session.Cache().SetRelation(&dbt.Relation{
		Type:      "managed_by",
		CreatedAt: now,
		LastSeen:  now,
		FromAsset: asn,
		ToAsset:   rir,
	})

	e.Session.Log().Info("relationship discovered", "from", 0, "relation",
		"managed_by", "to", "Reserved Network Address Blocks", group)

	if nb, err := e.Session.DB().Create(asn, "announces", netblock); err == nil && nb != nil {
		e.Session.Cache().SetAsset(nb)
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "announces",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: asn,
			ToAsset:   nb,
		})

		e.Session.Log().Info("relationship discovered", "from", 0,
			"relation", "announces", "to", netblock.Cidr.String(), group)
	}
}
