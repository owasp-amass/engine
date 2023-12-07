// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"net/netip"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type ipNetblock struct{}

func newIPNetblock() Plugin {
	return &ipNetblock{}
}

func (d *ipNetblock) Start(r *registry.Registry) error {
	name := "IP-Netblock-Handler"
	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Priority:   4,
		Transforms: []string{"netblock"},
		EventType:  oam.IPAddress,
		Handler:    d.lookup,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (d *ipNetblock) Stop() {}

// ipLookup function queries the bgptools whois server using an
// IP address to retrieve related ASN, netblock, and RIR details.
func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	session := e.Session.(*sessions.Session)
	matches, err := checkTransformations(session, "ipaddress", "netblock")
	if err != nil {
		return err
	}
	if _, ok := matches["netblock"]; !ok {
		return nil
	}

	var netblock *network.Netblock
	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		t := "IPv6"
		if prefix.Addr().Is4() {
			t = "IPv4"
		}

		netblock = &network.Netblock{
			Cidr: prefix,
			Type: t,
		}
	} else {
		var err error

		netblock, err = ipToNetblockWithAttempts(session, ip, 10, 500*time.Millisecond)
		if err != nil {
			return nil
		}
	}

	if nb, err := session.DB.Create(nil, "", netblock); err == nil {
		if a, err := session.DB.Create(nb, "contains", ip); err == nil {
			now := time.Now()

			session.Cache.SetRelation(&dbt.Relation{
				Type:      "contains",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: nb,
				ToAsset:   a,
			})
		}
	}
	return nil
}
